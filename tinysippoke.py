#!/usr/bin/env python3

"""
Tiny SIP Poke - Small script which can perform simple SIP OPTIONS ping and read response.
Deliberately written on pure python3 without external dependencies for compatibility with clean installations
of more or less actual Linux distributions (RHEL-like >8/9, Ubuntu >18.04 etc.)
"""
import sys
import uuid
import random
import argparse
import time
import re
import platform
import ssl
import logging

from abc import abstractmethod

from socket import SOL_SOCKET, SOL_IP, SO_REUSEADDR, SO_REUSEPORT, \
    SOCK_DGRAM, SOCK_STREAM, AF_INET, gethostbyname, gethostname

VERSION = "0.1"
TOOL_DESCRIPTION = "tinysippoke is small tool that sends SIP OPTIONS " \
                   "requests to remote host and reads responses. "

MAX_FORWARDS = 70  # times
DFL_PING_TIMEOUT = 1.0  # seconds
MAX_RECVBUF_SIZE = 1400  # bytes
DFL_SIP_PORT = 5060
DFL_REQS_COUNT = 0
DFL_SIP_TRANSPORT = "udp"
RTT_INFINITE = 99999999.0
DFL_SEND_PAUSE = 0.5
DFL_PAYLOAD_SIZE = 600  # bytes
DFL_FROM_USER = "tinysippoke"
DFL_TO_USER = "options"
DFL_TLS_SEC_LEVEL = 3
FAIL_EXIT_CODE = 1
FATAL_EXIT_CODE = 255

CA_PATH_DARWIN = "/etc/ssl/cert.pem"
CA_PATH_LINUX = "/etc/ssl/certs/ca-certificates.crt"  # Debian/Ubuntu path. Temporary path

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

# Unfortunately, Python2.7 had no such definitions in socket module
# Linux-specific definitions, taken from Linux in.h file for the cause
IP_MTU_DISCOVER = 10
IP_PMTUDISC_DONT = 0  # Never send DF frames
IP_PMTUDISC_WANT = 1  # Use per route hints
IP_PMTUDISC_DO = 2  # Always DF
IP_PMTUDISC_PROBE = 3  # Ignore dst pmtu

# length of this phrase * 1489 = totally 65536 bytes -- it's max theoretical size of UDP dgram
PADDING_PATTERN = "the_quick_brown_fox_jumps_over_the_lazy_dog_" * 1489

# messages templates for further formatting
MSG_SENDING_REQS = "Sending {} SIP OPTIONS request{} (size {}) {}to {}:{} with timeout {:.03f}s..."
MSG_RESP_FROM = "SEQ #{} ({} bytes sent) {}: Response from {} ({} bytes, {:.03f} sec RTT): {}"
MSG_DF_BIT_NOT_SUPPORTED = "WARNING: ignoring dont_set_df_bit (-m) option that is not supported by this platform"
MSG_UNABLE_TO_CONNECT = "FATAL: Unable to connect to {}:{}: {}"

SPLIT_URI_REGEX = re.compile(
    "(?:(?P<user>[\w\.]+):?(?P<password>[\w\.]+)?@)?"
    "\[?(?P<host>(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|"
    "(?:(?:[0-9a-fA-F]{1,4}):){7}[0-9a-fA-F]{1,4}|"
    "(?:(?:[0-9A-Za-z]+\.)+[0-9A-Za-z]+))\]?:?(?P<port>\d{1,6})?"
)


def _debug_print(*strings):
    """
    (for internal use only)
    Prints strings only if verbosity is on. Use it any time when you want to
    toggle messages output.
    :param verbose: (bool) Enables verbosity. If false, nothing will be printed
    :param strings: (list) list of strings
    """
    c = Config()
    if c.verbose_mode:
        for s in strings:
            print(s)

def _normal_print(*strings):
    """
    (for internal use only)
    Prints strings only if quiet mode is off. Use it any time when you want to
    toggle messages output.
    :param strings: (list) list of strings
    """
    c = Config()
    if not c.quiet_mode:
        for s in strings:
            print(s)


def singleton(cls):
    instances = {}

    def getinstance():
        if cls not in instances:
            instances[cls] = cls()
        return instances[cls]

    return getinstance


def logger_init(out=sys.stdout, level=logging.DEBUG):
    log = logging.getLogger()
    log.setLevel(level)
    handler = logging.StreamHandler(out)
    log.addHandler(handler)
    return log


@singleton
class Config:
    dst_host = ""  # value is to be filled below
    dst_port = DFL_SIP_PORT  # value may be redefined below
    bind_addr = ""
    bind_port = 0
    count = 0
    timeout = DFL_PING_TIMEOUT
    proto = "udp"
    verbose_mode = False
    quiet_mode = False   # print only final stats, but not intermediate messages. Has no explicit cli option
    bad_resp_is_fail = False
    pause_between_transmits = DFL_SEND_PAUSE
    payload_size = DFL_PAYLOAD_SIZE
    dont_set_df_bit = False
    from_user = DFL_FROM_USER
    to_user = DFL_TO_USER
    tls_sec_level = DFL_TLS_SEC_LEVEL
    from_domain = None  # will be set later
    to_domain = None  # will be set later
    ca_certs_path = ssl.get_default_verify_paths().cafile
    fail_count = None
    fail_perc = None
    content_type = "header"

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
        content_opts = ap.add_mutually_exclusive_group(required=False)

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
            help="Source iface [ip/hostname]:[port] (hostname part is optional, possible to type \":PORT\" form "
                 "to just set srcport)",
            type=str,
            action="store"
        )

        exit_nonzero_opts.add_argument(
            "-k",
            dest="fail_perc",
            help="Program exits with non-zero code if percentage of failed requests more than threshold",
            type=float,
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
            help="Pause between transmits (default 0.5, 0 for immediate send)",
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
        )

        content_opts.add_argument(
            "-C",
            dest="content_type",
            help="Content type (send payload inside P-Padding header or inside body in XML or JSON form)",
            type=str,
            action="store",
            choices=["header", "xml", "json"],
            default="header"
        )

        ap.add_argument(
            "-v",
            dest="verbose_mode",
            help="Verbose mode (show sent and received content)",
            action="store_true"
        )

        ap.add_argument("-V", action="version", version=VERSION)
        return ap

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
        self.overall_stats_format = "pretty_print"

        try:
            self.fail_count = args.fail_count
        except AttributeError:
            pass

        try:
            self.fail_perc = args.fail_perc
        except AttributeError:
            pass

        assert args.destination is not None
        if ":" in args.destination:
            self.dst_host, dst_port = args.destination.split(":")
            self.dst_port = int(dst_port)
        else:
            self.dst_host = args.destination

        if args.src_sock:
            if ":" in args.src_sock:
                self.bind_addr, bind_port = args.src_sock.split(":")
                self.bind_port = int(bind_port)
            else:
                self.bind_addr = args.src_sock

        # hc means hosts contact
        # is to be used as domain part if we have no exact From: domain
        hc = self.bind_addr if self.bind_addr else gethostname()

        if args.field_from:
            uri_components = SPLIT_URI_REGEX.search(args.field_from)
            if uri_components:
                fu, _, fd, fp = uri_components.groups()  # ignoring password part
                if fu:
                    self.from_user = fu

                # this block allows input string in "xxx@" format with empty user part
                # in this case domain part will be empty after pattern matching.
                # We take it from hostname or source interface address
                # so, you're able to have constant user part and variable domain part
                if not fd:
                    fd = hc
                self.from_domain = "{}:{}".format(fd, fp) if fp else fd
        else:
            self.from_domain = "{}:{}".format(hc, self.bind_port) if self.bind_port else hc

        if args.field_to:
            uri_components = SPLIT_URI_REGEX.search(args.field_to)
            if uri_components:
                tu, _, td, tp = uri_components.groups()  # ignoring password part
                if tu:
                    self.to_user = tu

                # As similar block above, this one allows input To: URI value in "xxx@" format with empty domain part
                if not td:
                    td = self.dst_host

                self.to_domain = "{}:{}".format(td, tp) if tp else td
        elif self.dst_port:
            self.to_domain = "{}:{}".format(self.dst_host, self.dst_port)
        else:
            self.to_domain = self.dst_host

        if not self.ca_certs_path:
            if platform.system() == "Darwin":
                self.ca_certs_path = CA_PATH_DARWIN
            elif platform.system() == "Linux":
                self.ca_certs_path = CA_PATH_LINUX

        self.content_type = args.content_type

        # if we need statistics format for passing to Zabbix/TICK/etc., we don't need any another stdout
        if self.overall_stats_format != "pretty_print":
            self.quiet_mode = True

        # ...but let's show them if we asked for verbose output
        if self.verbose_mode:
            self.quiet_mode = False


@singleton
class OverallStatistics:
    def __init__(self):
        self.last_seq_num = -1
        self.unordered_requests = 0
        self.results = []
        self.min_rtt = RTT_INFINITE
        self.max_rtt = 0.0
        self.avg_rtt = 0.0
        self.passed_requests = 0
        self.failed_requests = 0
        self.answered_requests = 0
        self.answered_perc = 0.0
        self.failed_perc = 0.0
        self.passed_perc = 0.0
        self.response_codes = {}
        self.socket_error_causes = {}
        self.total_requests = len(self.results)

    def calc_stats(self):
        total_rtt_sum = 0
        for i in self.results:
            if i["is_successful"]:
                self.passed_requests += 1
            else:
                self.failed_requests += 1

            if i["rtt"] >= 0:
                self.min_rtt = i["rtt"] if (i["rtt"] < self.min_rtt) else self.min_rtt
                self.max_rtt = i["rtt"] if (i["rtt"] > self.max_rtt) else self.max_rtt
                total_rtt_sum += i["rtt"]

            try:
                self.response_codes[int(i["resp_code"])] += 1
            except KeyError:  # it means there"s no such response code before
                self.response_codes[int(i["resp_code"])] = 1

            if i["error"]:
                cause_name = re.sub(r"\s+", "_", str(i["error"])).lower()
                try:
                    self.socket_error_causes[cause_name] += 1
                except KeyError:  # it means there"s no such response code before
                    self.socket_error_causes[cause_name] = 1
            else:
                self.answered_requests += 1

        try:
            del self.response_codes[0]  # 0 is a stub response code
        except KeyError:
            pass

        self.min_rtt = -1.0 if self.min_rtt == RTT_INFINITE else self.min_rtt
        self.avg_rtt = -1.0 if not self.answered_requests else float(total_rtt_sum) / float(self.answered_requests)
        self.answered_perc = float(self.answered_requests) * 100.0 / float(self.total_requests)
        self.failed_perc = float(self.failed_requests) * 100.0 / float(self.total_requests)
        self.passed_perc = 100.0 - self.failed_perc

    def to_dict(self):
        return {
            "total": self.total_requests,
            "passed": self.passed_requests,
            "failed": self.failed_requests,
            "failed_perc": self.failed_perc,
            "passed_perc": self.passed_perc,
            "answered": self.answered_requests,
            "answered_perc": self.answered_perc,
            "min_rtt": self.min_rtt,
            "max_rtt": self.max_rtt,
            "avg_rtt": self.avg_rtt,
            "response_codes": self.response_codes,
            "socket_error_causes": self.socket_error_causes,
        }

    def pretty_print(self):
        """
        Just prints statistics in pretty form
        """
        stats = self.to_dict()
        perc_fmt = "{:15s} {:5d} / {:0.3f}%"
        float_value_str = "{:15s} {:9.3f}"

        total_requests = stats["total"]

        print("\n")
        print("------ FINISH -------")
        print("{:15s} {:5d}".format("Total requests:", total_requests))
        print(perc_fmt.format("Answered:", stats["answered"], stats["answered_perc"]))
        print(perc_fmt.format("Passed:", stats["passed"], stats["passed_perc"]))
        print(perc_fmt.format("Failed:", stats["failed"], stats["failed_perc"]))

        print("\n")

        if stats["answered"]:
            print("RTT stats (in ms):")
            print(float_value_str.format("min.RTT:", stats["min_rtt"]))
            print(float_value_str.format("avg.RTT:", stats["avg_rtt"]))
            print(float_value_str.format("max.RTT:", stats["max_rtt"]))
            print("\n")

        if stats["socket_error_causes"]:
            print("Socket errors causes stats:")
            for k, v in stats["socket_error_causes"].items():
                cause_percentage = 100.0 * (float(v) / float(total_requests))
                print("{:15s} {:5s}/{:0.3f}%".format(str(k), str(v), cause_percentage))
            print("\n")

        if stats["response_codes"]:
            print("Response codes stats:")
            for k, v in stats["response_codes"].items():
                resp_code_percentage = 100.0 * (float(v) / float(total_requests))
                print(perc_fmt.format(str(k), v, resp_code_percentage))

    # todo
    def to_zabbix_fmt(self):
        pass

    # todo
    def to_tick_fmt(self):
        pass

    def __add__(self, other):
        # we assume that only usage of + operator is adding new single results to overall stats
        assert isinstance(other, SingleResult)
        self.results.append(other)


class SingleResult:
    def __init__(self, dst_host, seq_num, full_request, full_response, errmsg, start_time, end_time=time.time(),
                 negative_resp_is_fail=False):
        self.dst_host = dst_host
        self.start_time = start_time
        self.end_time = end_time
        self.full_request = full_request
        self.full_response = full_response
        self.successful = True
        self.request_length = len(full_request)
        self.response_length = len(full_response) if full_response else 0
        self.errmsg = errmsg  # exception for further handling
        self.rtt: -1.0  # round trip time
        self.brief_response: ""  # just heading string like SIP/2.0 200 OK or error message
        self.resp_code: 0  # response code
        self.full_response: ""
        self.start_time = start_time
        self.end_time = end_time
        self.seq_num = seq_num

        if self.errmsg:
            self.successful = False
            self.brief_response = str(errmsg)
        else:
            self.brief_response = full_response.split("\n")[0].strip()
            self.resp_code = int(self.brief_response.split(" ")[1])
            self.rtt = end_time - start_time
            if negative_resp_is_fail and self.resp_code >= 400:
                self.successful = False

    def pretty_print(self):
        """
        Prints one line with result of certain request
        """
        _msg_resp = MSG_RESP_FROM.format(
            self.seq_num,
            self.request_length,
            "PASS" if self.successful else "FAIL",
            self.dst_host,
            self.response_length,
            self.rtt,
            self.brief_response,
        )
        print(_msg_resp)
        _debug_print("Full request:", self.full_request)
        _debug_print("Full response:", self.full_response)
        _debug_print("{}\n".format("-" * len(_msg_resp)))

    def to_dict(self):
        return {
            "dst_host": self.dst_host,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "full_request": self.full_request,
            "full_response": self.full_response,
            "successful": self.successful,
            "request_length": self.request_length,
            "response_length": self.response_length,
            "errmsg": self.errmsg,
            "rtt": self.rtt,
            "brief_response": self.brief_response,
            "resp_code": self.resp_code,
            "seq_num": self.seq_num,
        }


# todo: Finish logic
class AbstractWorker:
    def __init__(self, *args, **kwargs):
        c = Config()
        self.get_payload = None
        if c.content_type == "xml":
            self.get_payload = self._render_request_with_xml
        elif c.content_type == "json":
            self.get_payload = self._render_request_with_json
        elif c.content_type == "header":
            self.get_payload = self._render_request_with_header

        self.overall_stats = OverallStatistics()
        self.real_init()


    @abstractmethod
    def real_init(self):
        # depends of socket type, os etc.
        pass

    @staticmethod
    def get_json_payload(payload_size=DFL_PAYLOAD_SIZE):
        """
        Generates payload in JSON form for further sending as request body
        :param payload_size: (int) Payload size (min. 15 because of JSON template length)
        :return: (str) String with payload inside XML with overall size equal to needed
        """
        # 15 is length of json template
        if payload_size > 15:
            return "{\"payload\": \"{}\"}".format(PADDING_PATTERN[payload_size - 15])
        else:
            return "{\"payload\": \"\"}"

    @staticmethod
    def get_xml_payload(payload_size=DFL_PAYLOAD_SIZE):
        """
        Generates payload in XML form for further sending as request body
        :param payload_size: (int) Payload size (min. 41 because of XML template length)
        :return: (str) String with payload inside XML with overall size equal to needed
        """
        # 41 is length of xml template (43 bytes) minus 2 bytes of {} placeholder
        if payload_size > 41:
            return "<?xml version=\"1.0\"?>\n<payload>{}</payload>".format(PADDING_PATTERN[payload_size - 41])
        else:
            return "<?xml version=\"1.0\"?>\n<payload> </payload>"

    @staticmethod
    def _render_mandatory_fields():
        """
        :returns: (list): list with SIP headers common for all forms
        """
        c = Config()
        # sender_contact will be used in Via: and Contact: headers
        # sc_host = sender contact's host part
        sc_host = c.bind_addr if c.bind_addr else gethostname()
        sender_contact = "{}:{}".format(sc_host, c.bind_port) if c.bind_port else sc_host

        # According to RFC3261, the branch ID MUST always begin with the characters
        # "z9hG4bK". It used as magic cookie. Beyond this requirement, the precise
        # format of the branch token is implementation-defined
        branch_id = "z9hG4bK{}".format(str(uuid.uuid4()))

        # these intervals are chosen to keep request size always constant
        cseq = random.randint(1000000000, 2147483647)
        tag_id = random.randint(1000000000, 2147483647)

        content_fields = [
            "OPTIONS sip:{}@{} SIP/2.0".format(c.to_user, c.to_domain),
            "Via: SIP/2.0/{} {};branch={};rport".format(c.proto.upper(), sender_contact, branch_id),
            "Max-Forwards: {}".format(MAX_FORWARDS),
            "To: <sip:{}@{}>".format(c.to_user, c.to_domain),
            "From: <sip:{}@{}>;tag={}".format(c.from_user, c.from_domain, tag_id),
            "Call-ID: {}".format(str(uuid.uuid4())),
            "CSeq: {} OPTIONS".format(cseq),
            "Contact: <sip:{}@{}>;transport={}".format(c.from_user, sender_contact, c.proto.lower()),
        ]
        return "\r\n".join(content_fields)

    def _render_request_with_header(self):
        """
        Generates serialized SIP header from source data with payload in P-Padding header
        :params (dict): dict with parameters of request
        :returns: (string): SIP header in human-readable format. Don"t forget to
                            encode it to bytes
        """
        c = Config()
        mandatory_content = self._render_mandatory_fields()
        req_without_padding = "\r\n".join([
            mandatory_content,
            "Accept: application/sdp",
            "Content-Length: 0",
            "P-Padding: {}",
            "\r\n"
        ])

        # + 2 because of {} placeholder that accounted in len(req_without_padding) but later will be substituted
        temp_padding_size = c.payload_size - len(req_without_padding) + 2
        padding_size = temp_padding_size if temp_padding_size > 0 else 1
        return req_without_padding.format(PADDING_PATTERN[padding_size:])

    def _render_request_with_json(self):
        """
        Generates serialized SIP request from source data with payload JSON body. Overall length is equal to requested
        :returns: (string): SIP request in human-readable format. Don"t forget to convert it to bytes
        """
        c = Config()
        mandatory_content = self._render_mandatory_fields()
        req_without_padding = "\r\n".join([
            mandatory_content,
            "Accept: application/json",
            "Content-Type: application/json",
            "Content-Length: {}",
            "\r\n",
            "{}"
        ])

        # + 4 because of two {} placeholders that accounted in len() but later will be substituted
        temp_padding_size = c.payload_size - len(req_without_padding) + 4
        padding_size = temp_padding_size if temp_padding_size > 0 else 1
        padding = self.get_json_payload(padding_size)
        return req_without_padding.format(len(padding), padding)

    def _render_request_with_xml(self):
        """
        Generates serialized SIP request from source data with payload XML body. Overall length is equal to requested
        :returns: (string): SIP request in human-readable format. Don"t forget to convert it to bytes
        """
        c = Config()
        mandatory_content = self._render_mandatory_fields()
        req_without_padding = "\r\n".join([
            mandatory_content,
            "Accept: application/xml",
            "Content-Type: application/xml",
            "Content-Length: {}",
            "\r\n",
            "{}"
            "\r\n"
        ])

        # + 4 because of two {} placeholders that accounted in len() but later will be substituted
        temp_padding_size = c.payload_size - len(req_without_padding) + 4
        padding_size = temp_padding_size if temp_padding_size > 0 else 1
        padding = self.get_xml_payload(padding_size)
        return req_without_padding.format(len(padding), padding)

    @abstractmethod
    def real_send_one_request(self):
        pass

    @abstractmethod
    def real_recv_one_response(self):
        pass

    # todo
    def send_one_request(self):
        _normal_print()

    # todo
    def recv_one_response(self):
        pass


# todo
class UDPWorker(AbstractWorker):
    pass


# todo
class TCPWorker(AbstractWorker):
    pass
