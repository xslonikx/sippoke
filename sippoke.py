import logging
import os
import socket
import uuid
import asyncio
import ssl
import argparse
import time
import platform
import re

from abc import abstractmethod
from statistics import mean, stdev
from signal import SIGINT, SIGTERM

VERSION = "0.0.1"
TOOL_DESCRIPTION = "sippoke is small tool that sends SIP OPTIONS requests to remote host and calculates latency."

MAX_FORWARDS = 70  # times
DFL_PING_TIMEOUT = 1.0  # seconds
DFL_SIP_PORT = 5060
DFL_REQS_COUNT = 0
DFL_SIP_TRANSPORT = "udp"
DFL_SEND_PAUSE = 0.5
DFL_PAYLOAD_SIZE = 600  # bytes
DFL_FROM_USER = "sippoke"
DFL_TO_USER = "options"
DFL_CSEQ = 1
DFL_TLS_SEC_LEVEL = 3
FAIL_EXIT_CODE = 1
CA_PATH_DARWIN = "/etc/ssl/cert.pem"
CA_PATH_LINUX = "/etc/ssl/certs/ca-certificates.crt"   # Debian/Ubuntu path. Temporary path

WEAK_CIPHERS = (
    "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES256-SHA:GOST2012256-GOST89-GOST89:"
    "DHE-RSA-CAMELLIA256-SHA:GOST2001-GOST89-GOST89:AES256-SHA:CAMELLIA256-SHA:ECDHE-RSA-AES128-SHA:"
    "ECDHE-ECDSA-AES128-SHA:DHE-RSA-AES128-SHA:DHE-RSA-CAMELLIA128-SHA:AES128-SHA:CAMELLIA128-SHA:"
    "ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:"
    "EDH-RSA-DES-CBC3-SHA:DES-CBC3-SHA"
)

DEFAULT_CIPHERS = (
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:"
    "ECDHE-ECDSA-AES256-SHA384:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-RSA-CAMELLIA256-SHA256:"
    "AES256-GCM-SHA384:AES256-SHA256:CAMELLIA256-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:"
    "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-CAMELLIA128-SHA256:AES128-GCM-SHA256:"
    "AES128-SHA256:CAMELLIA128-SHA256"
)

ALL_CIPHERS = "{}:{}".format(WEAK_CIPHERS, DEFAULT_CIPHERS)

# length of this phrase * 1489 = totally 65536 bytes -- it's max theoretical size of UDP dgram
PAYLOAD_PATTERN = "the_quick_brown_fox_jumps_over_the_lazy_dog_" * 1489

# messages templates for further formatting
MSG_DF_BIT_NOT_SUPPORTED = "WARNING: ignoring dont_set_df_bit (-m) option that is not supported by this platform"
MSG_UNABLE_TO_CONNECT = "FATAL: Unable to connect to {}:{}: {}"

RESPONSE_MESSAGE_IPV4 = ("Received       :: {data_length:6} byte{suffix} response from {endpoint:27} :: {status_line}"
                         " in {rtt:.3f}ms")
RESPONSE_MESSAGE_IPV6 = ("Received       :: {data_length:6} byte{suffix} response from {endpoint:45} :: {status_line}"
                         " in {rtt:.3f}ms")

SEND_MESSAGE_IPV4 = ("\nSent  #{current_req_count:<7} :: {msglen:6} byte{suffix} message  to   {endpoint:26}  ::"
                     " {req_string}")
SEND_MESSAGE_IPV6 = ("\nSent  #{current_req_count} :: {msglen:6} byte{suffix} message  to   [{endpoint:42}] ::"
                     " {req_string}")

SPLIT_URI_REGEX = re.compile(
    "(?:(?P<user>[\w.]+):?(?P<password>[\w.]+)?@)?\[?(?P<host>(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|"
    "\[(?:(?:[0-9a-fA-F]{1,4}:){1,7}:{0,1}[0-9a-fA-F]{0,4}\])|(?:(?:[0-9A-Za-z\-]+\.)+[0-9A-Za-z\-]+)){0,1}\]?"
    ":?(?P<port>\d{1,6})?"
)

SEQNUM_REGEX = re.compile(r"(?:Call-ID|i): .*_(\d+)", re.IGNORECASE | re.MULTILINE)

# Unfortunately, Python2.7 has no these definitions in socket module
# Linux-specific definitions, taken from Linux in.h file
IP_MTU_DISCOVER = 10
IP_PMTUDISC_DONT = 0  # Never send DF frames
IP_PMTUDISC_WANT = 1  # Use per route hints
IP_PMTUDISC_DO = 2  # Always DF
IP_PMTUDISC_PROBE = 3  # Ignore dst pmtu

ALL_POSSIBLE_TLS_VERSIONS = {
    "SSLv2": getattr(ssl.TLSVersion, "SSLv2", None),
    "SSLv3": getattr(ssl.TLSVersion, "SSLv3", None),
    "TLSv1.0": getattr(ssl.TLSVersion, "TLSv1", None),
    "TLSv1.1": getattr(ssl.TLSVersion, "TLSv1_1", None),
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}

AVAILABLE_TLS_VERSIONS = {k: v for k, v in ALL_POSSIBLE_TLS_VERSIONS.items() if v is not None }

def determine_ca_certs_path():
    if platform.system() == "Darwin":
        return CA_PATH_DARWIN
    elif platform.system() == "Linux":
        return CA_PATH_LINUX
    else:
        raise NotImplementedError(f"Unsupported platform: {platform.system()}")


class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
            return cls._instances[cls]
        else:
            return cls._instances[cls]


class Config(metaclass=Singleton):
    dst_host = ""  # value is to be filled below
    dst_port = DFL_SIP_PORT  # value may be redefined below
    bind_addr = ""
    bind_port = 0   # means any available source port
    count = 0
    timeout = DFL_PING_TIMEOUT
    proto = "udp"
    verbose_mode = False
    neg_resp_is_fail = False
    pause_between_transmits = DFL_SEND_PAUSE
    payload_size = DFL_PAYLOAD_SIZE
    dont_set_df_bit = False
    from_user = DFL_FROM_USER
    to_user = DFL_TO_USER
    tls_sec_level = DFL_TLS_SEC_LEVEL
    tls_no_verify_cert_totally=False
    tls_no_verify_cert_hostname_ca=False
    from_uri = None    # will be set later
    to_uri = None   # will be set later
    ca_certs_path = ssl.get_default_verify_paths().cafile
    fail_count = None
    fail_perc = None
    node_name = os.uname().nodename

    def __init__(self, args=None):
        self._get_params_from_args(self._prepare_argv_parser().parse_args())

    @staticmethod
    def _prepare_argv_parser():
        """
        (for internal use) Returns ArgumentParser with configured options and \
        help strings
        :returns: (argparse.ArgumentParser) object with cli options
        """
        ap = argparse.ArgumentParser(
            description=TOOL_DESCRIPTION,
            formatter_class=lambda prog: argparse.HelpFormatter(prog, width=120)
        )

        exit_nonzero_opts = ap.add_mutually_exclusive_group(required=False)
        tls_opts = ap.add_argument_group(title="TLS Options", description="make sense only with TLS protocol")
        sip_uri_opts = ap.add_argument_group(title="Custom SIP URI options")
        tls_verify_opts = tls_opts.add_mutually_exclusive_group(required=False)

        ap.add_argument(
            "destination",
            help="Destination host <dst>[:port] (default port {})".format(DFL_SIP_PORT),
            type=str,
            action="store",
        )

        ap.add_argument(
            "-c",
            dest="count",
            help="Number of requests, 0 for infinite ping (default)",
            type=int,
            default=0
        )

        ap.add_argument(
            "-F",
            dest="neg_resp_is_fail",
            help="Treat 4xx, 5xx, 6xx responses as failure (default no)",
            action="store_true"
        )

        ap.add_argument(
            "-i",
            dest="src_sock",
            help=("Source iface [ussrname]@[ip/hostname]:[port] (hostname part is optional, possible to type "
                  "\":PORT\" form to just set srcport)"),
            type=str,
            action="store"
        )

        exit_nonzero_opts.add_argument(
            "-k",
            dest="fail_perc",
            help="Program exits with non-zero code if percentage of failed requests more than threshold",
            type=float,
            default=0.0,
            action="store",
        )

        exit_nonzero_opts.add_argument(
            "-K",
            dest="fail_count",
            help="Program exits with non-zero code if count of failed requests more than threshold",
            type=int,
            action="store",
        )

        ap.add_argument(
            "-l",
            dest="pause_between_transmits",
            help=f"Pause between transmits (default {DFL_SEND_PAUSE}, 0 for immediate send)",
            action="store",
            type=float,
            default=DFL_SEND_PAUSE
        )

        ap.add_argument(
            "-m",
            dest="dont_set_df_bit",
            help="Do not set DF bit (default DF bit is set) "
                 "- currently works only on Linux",
            action="store_true",
        )

        ap.add_argument(
            "-p",
            dest="proto",
            help="Protocol (udp, tcp, tls)",
            type=str,
            action="store",
            choices=["tcp", "udp", "tls"],
            default=DFL_SIP_TRANSPORT,
        )

        ap.add_argument(
            "-s",
            dest="payload_size",
            help="Fill request up to certain size",
            type=int,
            action="store",
            default=DFL_PAYLOAD_SIZE
        )

        ap.add_argument(
            "-t",
            dest="sock_timeout",
            help="Socket timeout in seconds (float, default {:.01f})".format(DFL_PING_TIMEOUT),
            type=float,
            action="store",
            default=DFL_PING_TIMEOUT
        )

        tls_opts.add_argument(
            "-Tm",
            dest="tls_minimum_version",
            choices=AVAILABLE_TLS_VERSIONS.keys(),
            help="Minimum TLS version to use (depends of OS configuration)",
            type=str,
            action="store",
            default="TLSv1.2"
        )

        tls_opts.add_argument(
            "-TM",
            dest="tls_maximum_version",
            choices=AVAILABLE_TLS_VERSIONS.keys(),
            help="Maximum TLS version to use (depends of OS configuration)",
            type=str,
            action="store",
            default="TLSv1.3"
        )

        tls_opts.add_argument(
            "-Tc",
            dest="ca_certs_path",
            help="Custom CA certificates path",
            type=str,
            action="store",
            default=determine_ca_certs_path()
        )

        tls_verify_opts.add_argument(
            "-Tx",
            dest="tls_no_verify_cert_totally",
            help="Do not verify Server TLS certificate at all, any certificate is valid",
            action="store_true",
        )

        tls_verify_opts.add_argument(
            "-Th",
            dest="tls_no_verify_cert_hostname_ca",
            help="Do not verify hostname and CA in Server TLS certificate, but keep verifying the dates",
            action="store_true",
        )

        sip_uri_opts.add_argument(
            "-tU",
            dest="to_uri",
            help="Custom URI for Sip To: header (they may differ with actual destination)",
            type=str,
            action="store",
            default="",
        )

        sip_uri_opts.add_argument(
            "-fU",
            dest="from_uri",
            help="Custom URI for Sip From: header (they may differ with actual source)",
            type=str,
            action="store",
            default="",
        )

        ap.add_argument(
            "-v",
            dest="verbose_mode",
            help="Verbose mode (show sent and received content)",
            action="store_true"
        )

        ap.add_argument("-V",
            action="version",
            version=f"sippoke v.{VERSION} on {platform.platform()}/python{platform.python_version()}")
        return ap

    @staticmethod
    def _parse_address_string(string):
        # we do not need password part for SIP OPTIONS, but better to be able to accept it
        username, _, domain, port = SPLIT_URI_REGEX.search(string).groups()
        return username, domain, port

    @staticmethod
    def _is_zero_addr(addr):
        return True if addr in ("0.0.0.0", "[::]") else False

    def _get_params_from_args(self, args):
        """
        (for internal use only)
        Function returns dictionary with params taken from args.
        Dictionary content:
        {
            "dst_host": (str) Destination host. Assertion for not empty
            "dst_port": (int) Destination port.
            "bind_addr": (str) Source interface ip
            "bind_port": (int) Source port
            "count": (int) Count of requests that are to be sent
            "timeout": (float) Socket timeout
            "proto": Protocol (tcp or udp). Assertion for proto in (tcp, udp)
            "verbose_mode": (bool) Verbose mode
            "neg_resp_is_fail": (bool) Treat 4xx, 5xx, 6xx responses as fail
        }
        :param args: (argparse.Namespace) argparse CLI arguments
        :return: (dict) dictionary with params
        """
        self.count = args.count
        self.timeout = args.sock_timeout
        self.proto = args.proto
        self.verbose_mode = args.verbose_mode
        self.neg_resp_is_fail = args.neg_resp_is_fail
        self.pause_between_transmits = args.pause_between_transmits
        self.payload_size = args.payload_size
        self.dont_set_df_bit = args.dont_set_df_bit
        self.tls_no_verify_cert_totally = False
        self.tls_no_verify_cert_hostname_ca = False
        self.tls_maximum_version = None
        self.tls_minimum_version = None
        self.ca_certs_path = args.ca_certs_path
        self.to_uri = args.to_uri
        self.from_uri = args.from_uri

        try:
            self.fail_count = args.fail_count
        except AttributeError:
            pass

        try:
            self.fail_perc = args.fail_perc
        except AttributeError:
            pass

        assert args.destination is not None

        to_username, to_addr, to_port = self._parse_address_string(args.destination)
        self.dst_host = to_addr.strip()

        # initialize with defaults
        to_username = to_username.strip() if to_username else DFL_TO_USER
        self.dst_port = int(to_port) if to_port is not None else DFL_SIP_PORT
        if not self.to_uri:
            self.to_uri = f"{to_username}@{self.dst_host}"

        if not self.from_uri:
            self.from_uri = f"{DFL_FROM_USER}@{platform.node()}"

        if args.src_sock:
            from_username, from_addr, from_port = self._parse_address_string(args.src_sock)
            self.bind_addr = from_addr.strip() if from_addr and not self._is_zero_addr(from_addr) else None
            self.bind_port = int(from_port.strip()) if from_port is not None else 0
            from_user = from_username.strip() if from_username else DFL_FROM_USER
            from_domain = self.bind_addr.strip() if self.bind_addr.strip() else platform.node()

            if self.bind_port is not None:
                self.from_uri = f"{from_user}@{from_domain}:{self.bind_port}"
            else:
                self.from_uri = f"{from_user}@{from_domain}"

        if not self.to_uri:
            self.to_uri = f"{to_username}@{self.dst_host}:{self.dst_port}"

        self.tls_no_verify_cert_totally = args.tls_no_verify_cert_totally
        self.tls_no_verify_cert_hostname_ca = args.tls_no_verify_cert_hostname_ca
        self.tls_minimum_version = args.tls_minimum_version
        self.tls_maximum_version = args.tls_maximum_version


class SingleResult:
    def __init__(self):
        self.raw_data = None
        self.response_code = None
        self.status_line = None
        self.seqnum = None
        self.rtt = None
        self.error_string = None
        self.receive_status = ""

class Statistics(metaclass=Singleton):
    def __init__(self):
        self._pending_queue = {}
        self._received_queue = []
        self.c = Config()
        self.main_stats = {
            "sent": 0,
            "received": 0,
            "lost": 0,
            "passed": 0,
            "passed_perc": 0.0,
            "failed": 0,
            "failed_perc": 0.0,
            "malformed": 0,
            "malformed_perc": 0.0,
            "reordered": 0,
            "reordered_perc": 0.0,
            "lost_perc": 100.0,
            "min_latency": float("inf"),
            "max_latency": -float("inf"),
            "avg_latency": float("inf"),
            "max_jitter": float("inf"),
            "std_deviation": float("inf"),
        }

        self.resp_codes = {}
        self.resp_codes_percs = {}
        self.socket_errors = {}
        self.socket_errors_percs = {}

        self.current_seqnum = 0
        self._last_sent_seqnum= 0

    def add_to_queue(self, seqnum: int, start_time: float):
        self._pending_queue[seqnum] = start_time
        self.main_stats["sent"] += 1

    def get_seqnum(self) -> int:
        self._last_sent_seqnum = self.current_seqnum
        self.current_seqnum += 1
        return self._last_sent_seqnum

    def mark_received(self, single_result: SingleResult):
        try:
            if not single_result.receive_status == "malformed":
                self._received_queue.append(single_result.rtt)
                if single_result.seqnum < self._last_sent_seqnum:
                    self.main_stats["reordered"] += 1
                self.main_stats["received"] += 1
            else:
                self.main_stats["malformed"] += 1
        except (KeyError, TypeError):
            self.main_stats["malformed"] += 1

        if single_result.response_code:
            try:
                self.resp_codes[single_result.response_code] += 1
            except KeyError:
                self.resp_codes[single_result.response_code] = 1

    def get_send_time_for_seqnum(self, cseq: int) -> float:
        cseq_time = self._pending_queue.pop(cseq)
        return cseq_time

    def append_error_reason(self, error_reason: str):
        if error_reason:
            try:
                self.socket_errors[error_reason] += 1
            except KeyError:
                self.socket_errors[error_reason] = 1

    def pretty_print(self):
        perc_fmt = "{header:26s} {absolute:12d} / {percentage:0.3f}%"
        float_value_str = "{:22s} {:9.3f}"
        overall_result_message = "PASSED" if self.main_stats["overall_result"] else "FAILED"
        print(f"Overall status: {overall_result_message}")
        print(f"Total requests sent: {self.main_stats['sent']:18}")

        print(perc_fmt.format(
            header="Requests received:",
            absolute=self.main_stats["received"],
            percentage=100.0 - self.main_stats["lost_perc"],
        ))
        print("\nStatistics:")
        print(perc_fmt.format(
            header="Requests passed:",
            absolute=self.main_stats["passed"],
            percentage=self.main_stats["passed_perc"],
        ))
        print(perc_fmt.format(
            header="Requests failed:",
            absolute=self.main_stats["failed"],
            percentage=self.main_stats["failed_perc"],
        ))
        print(perc_fmt.format(
            header="Lost:",
            absolute=self.main_stats["lost"],
            percentage=self.main_stats["lost_perc"],
        ))
        print(perc_fmt.format(
            header="Reordered:",
            absolute=self.main_stats["reordered"],
            percentage=self.main_stats["reordered_perc"],
        ))
        print(perc_fmt.format(
            header="Malformed:",
            absolute=self.main_stats["malformed"],
            percentage=self.main_stats["malformed_perc"],
        ))

        if self.resp_codes:
            print("\nResponse codes statistics:")
            for code in self.resp_codes:
                print(perc_fmt.format(
                    header=str(code),
                    absolute=self.resp_codes[code],
                    percentage=self.resp_codes_percs[code],
                ))

        if self.socket_errors:
            print("\nNetwork errors statistics:")
            for e in self.socket_errors:
                print(perc_fmt.format(
                    header=str(e),
                    absolute=self.socket_errors[e],
                    percentage=self.socket_errors_percs[e],
                ))

    def finalize(self):
        if not self.main_stats["sent"]:
            self.main_stats["overall_result"] = False
            return

        self.main_stats["lost"] += len(self._pending_queue)

        # we treat lost as failed, but not all failed are lost
        self.main_stats["failed"] += len(self._pending_queue)

        if self.main_stats["sent"] > 0:
            self.main_stats["lost_perc"] = float(self.main_stats["lost"]) / float(self.main_stats["sent"]) * 100.0
        else:
            self.main_stats["lost_perc"] = 100.0

        self.main_stats["min_latency"] = min(self._received_queue) if self._received_queue else float("inf")
        self.main_stats["max_latency"] = max(self._received_queue) if self._received_queue else float("-inf")

        self.main_stats["max_jitter"] = self.main_stats["max_latency"] - self.main_stats["min_latency"] \
            if self._received_queue else float("inf")
        self.main_stats["avg_latency"] = mean(self._received_queue) if self._received_queue else float("inf")
        self.main_stats["std_deviation"] = stdev(self._received_queue) if len(self._received_queue) > 1 else 0.0

        for code in self.resp_codes:
            self.resp_codes_percs[code] = self.resp_codes[code] / float(self.main_stats["sent"]) * 100.0
            if  self.c.neg_resp_is_fail and code >= 400:
                self.main_stats["failed"] += self.resp_codes[code]

        for code in self.socket_errors:
            self.socket_errors_percs[code] = self.resp_codes[code] / float(self.main_stats["sent"]) * 100.0

        self.main_stats["passed"] = self.main_stats["sent"] - self.main_stats["failed"]
        self.main_stats["failed_perc"] = self.main_stats["failed"] / float(self.main_stats["sent"]) * 100.0
        self.main_stats["passed_perc"] = self.main_stats["passed"] / float(self.main_stats["sent"]) * 100.0
        self.main_stats["malformed_perc"] = self.main_stats["malformed"] / float(self.main_stats["sent"]) * 100.0
        self.main_stats["reordered_perc"] = self.main_stats["reordered"] / float(self.main_stats["sent"]) * 100.0

        if self.c.fail_perc:
            self.main_stats["overall_result"] = True if self.main_stats["failed_perc"] < self.c.fail_perc else False
        elif self.c.fail_count:
            self.main_stats["overall_result"] = True if self.main_stats["failed"] < self.c.fail_count else False
        else:
            self.main_stats["overall_result"] = True if self.main_stats["failed"] < self.main_stats["passed"] \
                                                 else False


class SIPOptionsBaseHandler(asyncio.Protocol):
    def __init__(self, on_con_lost):
        self.c = Config()
        self.dst_addr = None
        self.dst_port = None
        self.on_con_lost = on_con_lost
        self.transport = None
        self.stats = Statistics()
        self._response_message = None
        self._send_message = None
        self.current_req_count = 0
        self._address_family = None

    def connection_made(self, transport):
        self.transport = transport
        self.dst_addr, self.dst_port, *_ = self.transport.get_extra_info("peername")
        sock = self.transport.get_extra_info("socket")
        self._address_family = sock.family
        if self._address_family == socket.AF_INET:
            self._response_message = RESPONSE_MESSAGE_IPV4
            self._send_message = SEND_MESSAGE_IPV4
        elif self._address_family == socket.AF_INET6:
            self._response_message = RESPONSE_MESSAGE_IPV6
            self._send_message = SEND_MESSAGE_IPV6
        else:
            logging.fatal("Address family {sock.family} is not supported}")

        if platform.system() == "Linux":
            # small platform-specific notices
            # df bit often set on linux systems because pmtu discovery often enabled by default
            # but better not to rely on it and explicitly set and unset this
            if self.c.dont_set_df_bit:
                if self._address_family == socket.AF_INET:
                    sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
                else:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_DONTFRAG, 1)

    def _data_receiver_func(self, data, addr):
        data_length = len(data)
        suffix = "s" if len(data) > 1 else ""
        single_result = self.parse_received_data(data)
        if self.c.verbose_mode:
            print(f"\n--- Raw response:")
            print(data.decode())
        self.stats.mark_received(single_result)
        host, port, *_ = addr
        if single_result.receive_status != "malformed":
            print(self._response_message.format(
                data_length=data_length,
                suffix=suffix,
                endpoint=f"{host}:{port}" if self._address_family == socket.AF_INET else f"[{host}]:{port}",
                status_line=single_result.status_line,
                rtt=single_result.rtt)
            )
        else:
            print("Warning - malformed response received")

    def datagram_received(self, data, addr):
        """
        for UDP handler
        """
        self._data_receiver_func(data, addr)

    def data_received(self, data):
        """
        for TCP handler
        """
        self._data_receiver_func(data, (self.dst_addr, self.dst_port))

    def parse_received_data(self, data):
        result = SingleResult()
        receive_time = time.time()
        content = data.decode()
        try:
            raw_status_line, other_headers = content.split("\r\n",maxsplit=1)
            try:
                protocol, resp_code, resp_text = raw_status_line.split(" ", maxsplit=2)
                if "SIP" in protocol:
                    result.response_code = int(resp_code)
                    result.status_line = raw_status_line
            except (IndexError, ValueError):
                result.receive_status = "malformed"
        except ValueError:
            result.receive_status = "malformed"

        result.raw_data = content
        # because we use unique cseq and operate only with SIP OPTIONS, we can skip analyzing
        #try:
        groups = SEQNUM_REGEX.search(content).groups()
        result.seqnum = int(SEQNUM_REGEX.search(content).group(1))
        send_time = self.stats.get_send_time_for_seqnum(result.seqnum)
        if send_time:
            result.rtt = receive_time - send_time
            result.receive_status = "ok"
        else:
            result.receive_status = "unknown"
        #except (ValueError, AttributeError):
        #    result.receive_status = "malformed"
        return result

    def error_received(self, exc):
        print('Error received:', exc)
        stats = Statistics()

    def connection_lost(self, exc):
        self.on_con_lost.set_result(True)

    def create_request(self):
        seqnum = self.stats.get_seqnum()
        req_string = f"OPTIONS sip:{self.c.to_uri} SIP/2.0"
        message = "\r\n".join([
            req_string,
            f"Via: SIP/2.0/{self.c.proto.upper()} {self.c.node_name};branch=z9hG4bK{uuid.uuid4()};rport",
            f"Max-Forwards: 70",
            f"To: <sip:{self.c.to_uri}>",
            f"From: <sip:{self.c.from_uri}>;tag={uuid.uuid4()}",
            f"Call-ID: {uuid.uuid4()}_{seqnum}",
            f"CSeq: {DFL_CSEQ} OPTIONS",
            f"Contact: <sip:{self.c.from_uri}>;transport={self.c.proto.lower()}",
            "P-SipPoke-Payload: {}",
            "Content-Length: 0",
            "Accept: application/sdp",
            "\r\n"  # for getting double \r\n at the end, as it need by RFC
        ])

        msglen_without_payload = len(message)
        needed_payload_length = self.c.payload_size - msglen_without_payload + 2  # 2 bytes is placeholder {} itself
        needed_payload_length = needed_payload_length if needed_payload_length > 0 else 0
        payload = PAYLOAD_PATTERN[:needed_payload_length]
        message = message.format(payload)
        return req_string, seqnum, message

    @abstractmethod
    def _send(self, message):
        """
        Abstraction for actual sending method that differs in tcp and udp case
        """
        pass

    def send(self):
        send_time = time.time()
        req_string, cseq, message = self.create_request()
        self._send(message)
        if self.c.verbose_mode:
            print("\n--- Raw request")
            print(message)
        snd_msg = self._send_message.format(
            msglen=len(message),
            suffix="s" if len(message) > 1 else "",
            endpoint=f"{self.c.dst_host}:{self.c.dst_port}",
            current_req_count=self.current_req_count,
            req_string=req_string
        )

        print(snd_msg)
        self.stats.add_to_queue(cseq, send_time)
        self.current_req_count += 1

class SIPOptionsUDPHandler(SIPOptionsBaseHandler):
    def _send(self, message):
        self.transport.sendto(message.encode())


class SIPOptionsTCPHandler(SIPOptionsBaseHandler):
    def _send(self, message):
        self.transport.write(message.encode())


async def send_loop(protocol):
    c = Config()
    s = Statistics()
    try:
        if not c.count:
            while True:
                protocol.send()
                await asyncio.sleep(c.pause_between_transmits)
        else:
            while s.current_seqnum < c.count:
                protocol.send()
                await asyncio.sleep(c.pause_between_transmits)
    except asyncio.CancelledError:
        print("TEST Cancelled")
    finally:
        pass

async def stop_send_loop(loop, task):
    try:
        await task
    except KeyboardInterrupt:
        task.cancel()  # Cancel the running task gracefully
        await asyncio.gather(task, return_exceptions=True)
    finally:
        show_statistics()


def show_statistics():
    print("\n=========== FINISHED ===========")
    stats = Statistics()
    stats.finalize()
    stats.pretty_print()


async def main():
    # Get a reference to the event loop as we plan to use
    # low-level APIs.
    loop = asyncio.get_running_loop()
    on_con_lost = loop.create_future()
    transport = None
    protocol = None
    c = Config()
    s = Statistics()

    # primitive check for ipv6 address format
    dst_repr = f"{c.dst_host}:{c.dst_port}" if ":" not in c.dst_host else f"[{c.dst_host}]:{c.dst_port}"

    if c.bind_addr:
        src_repr = c.bind_addr if ":" not in c.bind_addr else f"[{c.bind_addr}]"
        src_repr = src_repr if not c.bind_port else f"{src_repr}:{c.bind_port}"
        print(f"Starting to send SIP OPTIONS from {src_repr} to {dst_repr} with size {c.payload_size}\n")
    else:
        print(f"Starting to send SIP OPTIONS to {dst_repr} with size {c.payload_size}\n")

    reuse_port = True if platform.system() in ["Linux", "Darwin"] else False

    if c.proto == "udp":
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: SIPOptionsUDPHandler(on_con_lost=on_con_lost),
            remote_addr=(c.dst_host, c.dst_port),
            local_addr=(c.bind_addr, c.bind_port) if c.bind_addr else None,
            reuse_port=reuse_port,
        )

    elif c.proto == "tcp":
        transport, protocol = await loop.create_connection(
            lambda: SIPOptionsTCPHandler(on_con_lost=on_con_lost),
            host=c.dst_host,
            port=c.dst_port,
            local_addr=(c.bind_addr, c.bind_port) if c.bind_addr else None,
        )

    elif c.proto == "tls":
        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ssl_context.load_verify_locations(c.ca_certs_path)

        if c.tls_no_verify_cert_totally:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        elif c.tls_no_verify_cert_hostname_ca:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_OPTIONAL

        try:
            if c.tls_maximum_version:
                ssl_context.maximum_version = AVAILABLE_TLS_VERSIONS[c.tls_maximum_version]
            if c.tls_maximum_version:
                ssl_context.minimum_version = AVAILABLE_TLS_VERSIONS[c.tls_minimum_version]
        except ValueError as e:
            print(f"Fatal error:\n{str(e)}")
            exit(1)

        try:
            transport, protocol = await loop.create_connection(
                lambda: SIPOptionsTCPHandler(on_con_lost=on_con_lost),
                host=c.dst_host,
                port=c.dst_port,
                local_addr=(c.bind_addr, c.bind_port) if c.bind_addr else None,
                ssl=ssl_context,
            )
        except (ssl.SSLError, socket.error, OSError) as e:
            print(f"Fatal error :\n{str(e)}")
            exit(1)

    task = loop.create_task(send_loop(protocol))
    try:
        await stop_send_loop(loop, task)
    finally:
        transport.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted")
    except asyncio.exceptions.CancelledError:
        pass
    except (ssl.SSLError, socket.error, OSError) as e:
        print(f"Fatal error:\n{str(e)}")
        exit(1)






