# sippoke
SIP Poke - Small script which can perform simple SIP OPTIONS ping and read 
responses. Further development of [Tinysipping](https://github.com/xslonikx/tinysipping) tool.  
  
Deliberately written in python3.8 style without external dependencies for compatibility with clean installations of 
more or less actual Linux distributions (RHEL-like >8/9, Ubuntu >18.04 etc.)  
  
```
sippoke is small tool that sends SIP OPTIONS requests to remote host and calculates latency.

positional arguments:
  destination           Destination host <dst>[:port] (default port 5060)

options:
  -h, --help            show this help message and exit
  -c COUNT              Number of requests, 0 for infinite ping (default)
  -F                    Treat 4xx, 5xx, 6xx responses as failure (default no)
  -i SRC_SOCK           Source iface [ussrname]@[ip/hostname]:[port] (hostname part is optional, possible to type
                        ":PORT" form to just set srcport)
  -k FAIL_PERC          Program exits with non-zero code if percentage of failed requests more than threshold
  -K FAIL_COUNT         Program exits with non-zero code if count of failed requests more than threshold
  -l PAUSE_BETWEEN_TRANSMITS
                        Pause between transmits (default 0.5, 0 for immediate send)
  -m                    Do not set DF bit (default DF bit is set) - currently works only on Linux
  -p {tcp,udp,tls}      Protocol (udp, tcp, tls)
  -s PAYLOAD_SIZE       Fill request up to certain size
  -t SOCK_TIMEOUT       Socket timeout in seconds (float, default 1.0)
  -v                    Verbose mode (show sent and received content)
  -V                    show program's version number and exit

TLS Options:
  make sense only with TLS protocol

  -Tm {SSLv3,TLSv1.0,TLSv1.1,TLSv1.2,TLSv1.3}
                        Minimum TLS version to use (depends of OS configuration)
  -TM {SSLv3,TLSv1.0,TLSv1.1,TLSv1.2,TLSv1.3}
                        Maximum TLS version to use (depends of OS configuration)
  -Tc CA_CERTS_PATH     Custom CA certificates path
  -Tx                   Do not verify Server TLS certificate at all, any certificate is valid
  -Th                   Do not verify hostname and CA in Server TLS certificate, but keep verifying the dates

Custom SIP URI options:
  -tU TO_URI            Custom URI for Sip To: header (they may differ with actual destination)
  -fU FROM_URI          Custom URI for Sip From: header (they may differ with actual source)

```

Example of usage:

```
$ python3 ./sippoke.py 127.0.0.1 -c 3 -F
Starting to send SIP OPTIONS to 127.0.0.1:5060 with size 600


Sent  #0       ::    600 bytes message  to   127.0.0.1:5060              :: OPTIONS sip:options@127.0.0.1 SIP/2.0
Received       ::    404 bytes response from 127.0.0.1:5060              :: SIP/2.0 404 Not Found in 0.001ms

Sent  #1       ::    600 bytes message  to   127.0.0.1:5060              :: OPTIONS sip:options@127.0.0.1 SIP/2.0
Received       ::    404 bytes response from 127.0.0.1:5060              :: SIP/2.0 404 Not Found in 0.001ms

Sent  #2       ::    600 bytes message  to   127.0.0.1:5060              :: OPTIONS sip:options@127.0.0.1 SIP/2.0
Received       ::    404 bytes response from 127.0.0.1:5060              :: SIP/2.0 404 Not Found in 0.001ms
^CTEST Cancelled

=========== FINISHED ===========
Overall status: FAILED
Total requests sent:                  3
Requests received:                    3 / 100.000%

Statistics:
Requests passed:                      0 / 0.000%
Requests failed:                      3 / 100.000%
Lost:                                 0 / 0.000%
Reordered:                            0 / 0.000%
Malformed:                            0 / 0.000%

Response codes statistics:
404                                   3 / 100.000%

```