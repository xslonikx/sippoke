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
from logging import fatal

from pprint import pprint
from statistics import mean, stdev

COUNTER_SENT = 0
COUNTER_RECEIVED = 0


VERSION = "0.0.1'"
TOOL_DESCRIPTION = "sippoke is small tool that sends SIP OPTIONS requests to remote host and calculates latency."

MAX_FORWARDS = 70  # times
DFL_PING_TIMEOUT = 1.0  # seconds
MAX_RECVBUF_SIZE = 1400  # bytes
DFL_SIP_PORT = 5060
DFL_REQS_COUNT = 0
DFL_SIP_TRANSPORT = "udp"
RTT_INFINITE = 99999999.0
DFL_SEND_PAUSE = 0.5
DFL_PAYLOAD_SIZE = 600  # bytes
DFL_FROM_USER = "sippoke"
DFL_TO_USER = "options"
DFL_TLS_SEC_LEVEL = 3
FAIL_EXIT_CODE = 1
START_CSEQ = 1000   # to have constant-length CSeq field
END_CSEQ = 2147483646
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

# Unfortunately, Python2.7 has no these definitions in socket module
# Linux-specific definitions, taken from Linux in.h file
IP_MTU_DISCOVER = 10
IP_PMTUDISC_DONT = 0  # Never send DF frames
IP_PMTUDISC_WANT = 1  # Use per route hints
IP_PMTUDISC_DO = 2  # Always DF
IP_PMTUDISC_PROBE = 3  # Ignore dst pmtu

# length of this phrase * 1489 = totally 65536 bytes -- it's max theoretical size of UDP dgram
PAYLOAD_PATTERN = "the_quick_brown_fox_jumps_over_the_lazy_dog_" * 1489

# messages templates for further formatting
MSG_SENDING_REQS = "Sending {} SIP OPTIONS request{} (size {}) {}to {}:{} with timeout {:.03f}s..."
MSG_RESP_FROM = "SEQ #{} ({} bytes sent) {}: Response from {} ({} bytes, {:.03f} sec RTT): {}"
MSG_DF_BIT_NOT_SUPPORTED = "WARNING: ignoring dont_set_df_bit (-m) option that is not supported by this platform"
MSG_UNABLE_TO_CONNECT = "FATAL: Unable to connect to {}:{}: {}"

RESPONSE_MESSAGE_IPV4 = "Received {data_length} byte{suffix} from {host}:{port} :: {status_line} in {rtt:.3f}ms"
RESPONSE_MESSAGE_IPV6 = "Received {data_length} byte{suffix} from [{host}]:{port} :: {status_line} in {rtt:.3f}ms"

SPLIT_URI_REGEX = re.compile(
    "(?:(?P<user>[\w.]+):?(?P<password>[\w.]+)?@)?\[?(?P<host>(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|"
    "\[(?:(?:[0-9a-fA-F]{1,4}:){1,7}:{0,1}[0-9a-fA-F]{0,4}\])|(?:(?:[0-9A-Za-z]+\.)+[0-9A-Za-z]+)){0,1}\]?"
    ":?(?P<port>\d{1,6})?"
)

CSEQ_REGEX = re.compile(r"CSeq: (\d+)", re.IGNORECASE | re.MULTILINE)


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
    bind_port = 0
    count = 0
    timeout = DFL_PING_TIMEOUT
    proto = "udp"
    verbose_mode = False
    bad_resp_is_fail = False
    pause_between_transmits = DFL_SEND_PAUSE
    payload_size = DFL_PAYLOAD_SIZE
    dont_set_df_bit = False
    from_user = DFL_FROM_USER
    to_user = DFL_TO_USER
    tls_sec_level = DFL_TLS_SEC_LEVEL
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
            default=DFL_REQS_COUNT
        )

        ap.add_argument(
            "-f",
            dest="bad_resp_is_fail",
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
            "-P",
            dest="proto",
            help="Protocol (udp, tcp, tls)",
            type=str,
            action="store",
            choices=["tcp", "udp", "tls"],
            default=DFL_SIP_TRANSPORT,
        )

        sip_uri_opts.add_argument(
            "-Rf",
            dest="field_from",
            help="SIP From: and Contact: URI",
            type=str,
            action="store",
        )

        sip_uri_opts.add_argument(
            "-Rt",
            dest="field_to",
            help="SIP To: and R-URI",
            type=str,
            action="store",
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
            "-Tl",
            dest="tls_sec_level",
            choices=[0, 1, 2, 3, 4, 5],
            help="OpenSSL security level - more is secure. Zero means enabling all insecure ciphers",
            type=int,
            action="store",
            default=3
        )

        tls_opts.add_argument(
            "-Tc",
            dest="ca_certs_path",
            help="Custom CA certificates path",
            type=str,
            action="store",
            default=determine_ca_certs_path()
        )

        tls_opts.add_argument(
            "-tU",
            dest="to_uri",
            help="Custom URI for Sip To: header (they may differ with actual destination)",
            type=str,
            action="store",
            default="",
        )

        tls_opts.add_argument(
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

        ap.add_argument("-V", action="version", version=VERSION)
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
            "bad_resp_is_fail": (bool) Treat 4xx, 5xx, 6xx responses as fail
        }
        :param args: (argparse.Namespace) argparse CLI arguments
        :return: (dict) dictionary with params
        """
        self.count = args.count
        self.timeout = args.sock_timeout
        self.proto = args.proto
        self.verbose_mode = args.verbose_mode
        self.bad_resp_is_fail = args.bad_resp_is_fail
        self.pause_between_transmits = args.pause_between_transmits
        self.payload_size = args.payload_size
        self.dont_set_df_bit = args.dont_set_df_bit
        self.tls_sec_level = args.tls_sec_level
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


class SingleResult:
    def __init__(self):
        self.raw_data = None
        self.response_code = None
        self.status_line = None
        self.cseq = None
        self.rtt = None
        self.error_string = None
        self.receive_status = ""


class Statistics(metaclass=Singleton):
    def __init__(self):
        self._pending_queue = {}
        self._received_queue = []

        self._main_stats = {
            "sent": 0,
            "received": 0,
            "lost": 0,
            "malformed": 0,
            "reordered": 0,
            "loss_percent": 100.0,
            "min_latency": float("inf"),
            "max_latency": -float("inf"),
            "avg_latency": float("inf"),
            "max_jitter": float("inf"),
            "std_deviation": float("inf"),
        }

        self._response_codes_stats = {}
        self._socket_errors_stats = {}

        self._current_cseq = START_CSEQ
        self._last_sent_cseq = START_CSEQ

    def add_to_queue(self, cseq: int, start_time: float):
        self._pending_queue[cseq] = start_time
        self._main_stats["sent"] += 1

    def get_cseq(self) -> int:
        self._last_sent_cseq = self._current_cseq
        self._current_cseq += 1
        return self._last_sent_cseq

    def mark_received(self, single_result: SingleResult):
        try:
            self._received_queue.append(single_result.rtt)
            self._main_stats["received"] += 1
            if single_result.cseq < self._last_sent_cseq:
                self._main_stats["reordered"] += 1
        except KeyError:
            self._main_stats["malformed"] += 1

        if single_result.response_code:
            try:
                self._response_codes_stats[single_result.response_code] += 1
            except KeyError:
                self._response_codes_stats[single_result.response_code] = 1

    def get_send_time_for_cseq(self, cseq: int) -> float:
        cseq_time = self._pending_queue.pop(cseq)
        return cseq_time

    def append_error_reason(self, error_reason: str):
        if error_reason:
            try:
                self._socket_errors_stats[error_reason] += 1
            except KeyError:
                self._socket_errors_stats[error_reason] = 1

    def increment_unknown(self):
        self._main_stats["malformed"] += 1

    def pretty_print(self):
        pprint(self._main_stats)

    def finalize(self):
        self._main_stats["lost"] += len(self._pending_queue)
        if self._main_stats["sent"] > 0:
            self._main_stats["loss_percent"] = float(self._main_stats["lost"]) / float(self._main_stats["sent"]) * 100.0
        else:
            self._main_stats["loss_percent"] = 100.0

        self._main_stats["min_latency"] = min(self._received_queue) if self._received_queue else float("inf")
        self._main_stats["max_latency"] = max(self._received_queue) if self._received_queue else float("-inf")

        self._main_stats["max_jitter"] = self._main_stats["max_latency"] - self._main_stats["min_latency"] \
            if self._received_queue else float("inf")
        self._main_stats["avg_latency"] = mean(self._received_queue) if self._received_queue else float("inf")
        self._main_stats["std_deviation"] = stdev(self._received_queue) if len(self._received_queue) > 1 else 0.0


class SIPOptionsHandler(asyncio.Protocol):
    def __init__(self, on_con_lost):
        self.c = Config()
        self.dst_addr = None
        self.dst_port = None
        self.on_con_lost = on_con_lost
        self.transport = None
        self.stats = Statistics()
        self._response_message = None

    def connection_made(self, transport):
        self.transport = transport
        self.dst_addr, self.dst_port, *_ = self.transport.get_extra_info("peername")
        sock = self.transport.get_extra_info("socket")
        if sock.family == socket.AF_INET:
            self._response_message = RESPONSE_MESSAGE_IPV4
        elif sock.family == socket.AF_INET6:
            self._response_message = RESPONSE_MESSAGE_IPV6
        else:
            logging.fatal("Address family {sock.family} is not supported}")

        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)


    def datagram_received(self, data, addr):
        data_length = len(data)
        suffix = "s" if len(data) > 1 else ""

        single_result = self.parse_received_data(data)
        self.stats.mark_received(single_result)
        host, port, *_ = addr
        print(self._response_message.format(
            data_length=data_length,
            suffix=suffix,
            host=host,
            port=port,
            status_line=single_result.status_line,
            rtt=single_result.rtt)
        )
        print(f"Raw response:", data.decode())

    def parse_received_data(self, data):
        result = SingleResult()
        receive_time = time.time()
        content = data.decode()
        raw_status_line, other_headers = content.split("\r\n",maxsplit=1)
        result.raw_data = content

        try:
            _, resp_code, resp_text = raw_status_line.split(" ", maxsplit=2)
            result.resp_code = int(resp_code)
            result.status_line = raw_status_line
        except (IndexError, ValueError):
            result.receive_status = "malformed"

        # because we use unique cseq and operate only with SIP OPTIONS, we can skip analyzing
        try:
            result.cseq = int(CSEQ_REGEX.search(content).group(1))
        except (ValueError, AttributeError):
            result.receive_status = "malformed"
        send_time = self.stats.get_send_time_for_cseq(result.cseq)
        if send_time:
            result.rtt = receive_time - send_time
            result.receive_status = "ok"
        else:
            result.receive_status = "unknown"
        return result

    def error_received(self, exc):
        print('Error received:', exc)
        stats = Statistics()


    def connection_lost(self, exc):
        self.on_con_lost.set_result(True)

    async def send_loop(self):
        while True:
            cseq = self.stats.get_cseq()
            message = "\r\n".join([
                f"OPTIONS sip:{self.c.to_uri} SIP/2.0",
                f"Via: SIP/2.0/{self.c.proto.upper()} {self.c.node_name};branch=z9hG4bK{uuid.uuid4()};rport",
                f"Max-Forwards: 70",
                f"To: <sip:{self.c.to_uri}>",
                f"From: <sip:{self.c.from_uri}>;tag={uuid.uuid4()}",
                f"Call-ID: {uuid.uuid4()}",
                f"CSeq: {cseq} OPTIONS",
                f"Contact: <sip:{self.c.from_uri}>;transport={self.c.proto.lower()}",
                "P-SipPoke-Payload: {}",
                "Content-Length: 0",
                "Accept: application/sdp",
                "\r\n"  # for getting double \r\n at the end, as it need by RFC
            ])

            msglen_without_payload = len(message)
            needed_payload_length = self.c.payload_size - msglen_without_payload + 2 # 2 bytes is placeholder {} itself
            needed_payload_length = needed_payload_length if needed_payload_length > 0 else 0
            payload = PAYLOAD_PATTERN[:needed_payload_length]
            message = message.format(payload)

            send_time = time.time()
            self.transport.sendto(message.encode())
            self.stats.add_to_queue(cseq, send_time)
            await asyncio.sleep(self.c.pause_between_transmits)


async def main():
    # Get a reference to the event loop as we plan to use
    # low-level APIs.
    loop = asyncio.get_running_loop()
    on_con_lost = loop.create_future()
    c = Config()
    print(f"Starting sippoke with packet len {c.payload_size}")

    local_addr = (c.bind_addr, c.bind_port) if c.bind_addr else None
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: SIPOptionsHandler(on_con_lost=on_con_lost),
        remote_addr=(c.dst_host, c.dst_port),
        local_addr=local_addr,
    )

    try:
        while True:
            await protocol.send_loop()
    except asyncio.CancelledError:
        transport.close()
    finally:
        transport.close()

def finish():
    stats = Statistics()
    print("=========== FINISHED ===========")
    stats.finalize()
    stats.pretty_print()

try:
    asyncio.run(main())
except KeyboardInterrupt:
    finish()



