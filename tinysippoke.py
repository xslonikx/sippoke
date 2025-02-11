import random
import sys
import uuid
import asyncio

COUNTER_SENT = 0
COUNTER_RECEIVED = 0

class EchoClientProtocol(asyncio.Protocol):
    def __init__(self, on_con_lost):
        self.destination_ip = None
        self.destination_port = None
        self.on_con_lost = on_con_lost
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        self.destination_ip = self.transport.get_extra_info('peername')[0]
        self.destination_port = self.transport.get_extra_info('peername')[1]

    def datagram_received(self, data, addr):
        global COUNTER_RECEIVED
        print("Received:", data.decode())
        COUNTER_RECEIVED += 1

    def error_received(self, exc):
        print('Error received:', exc)

    def connection_lost(self, exc):
        print("Connection closed")
        self.on_con_lost.set_result(True)

    async def send_loop(self):
        global COUNTER_SENT
        while True:
            message = "\r\n".join([
                f"OPTIONS sip:pinger@{self.destination_ip}:{self.destination_port} SIP/2.0",
                f"Via: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bK{uuid.uuid4()};rport",
                f"Max-Forwards: 70",
                f"To: <sip:pinger@{self.destination_ip}>",
                f"From: <sip:pinger@pinger>;tag={uuid.uuid4()}",
                f"Call-ID: {uuid.uuid4()}",
                f"CSeq: {random.randint(1000000000, 2000000000)} OPTIONS",
                "Contact: <sip:pinger@pinger>;transport=udp",
                "Accept: application/sdp",
                "Content-Length: 0",
                "\r\n"  # for getting double \r\n at the end, as it need by RFC
            ])
            self.transport.sendto(message.encode())
            COUNTER_SENT += 1
            await asyncio.sleep(0.5)


async def main():
    # Get a reference to the event loop as we plan to use
    # low-level APIs.
    loop = asyncio.get_running_loop()

    on_con_lost = loop.create_future()


    transport, protocol = await loop.create_datagram_endpoint(
        lambda: EchoClientProtocol(on_con_lost=on_con_lost),
        remote_addr=(sys.argv[1], 5060)
    )

    try:
        while True:
            await protocol.send_loop()
    except asyncio.CancelledError:
        transport.close()
    finally:
        transport.close()


try:
    asyncio.run(main())
except KeyboardInterrupt:
    print('Closing the socket')
    print(f"Sent: {COUNTER_SENT}")
    print(f"Received: {COUNTER_RECEIVED}")



