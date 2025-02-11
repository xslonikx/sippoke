import random
import sys
import uuid
import asyncio


class EchoClientProtocol(asyncio.Protocol):
    def __init__(self, destination_ip, destination_port, on_con_lost):
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.on_con_lost = on_con_lost
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        print("Received:", data.decode())

    def error_received(self, exc):
        print('Error received:', exc)

    def connection_lost(self, exc):
        print("Connection closed")
        self.on_con_lost.set_result(True)

    async def send_loop(self):
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
            await asyncio.sleep(0.5)


async def main():
    # Get a reference to the event loop as we plan to use
    # low-level APIs.
    loop = asyncio.get_running_loop()

    on_con_lost = loop.create_future()


    transport, protocol = await loop.create_datagram_endpoint(
        lambda: EchoClientProtocol(
            destination_ip=sys.argv[1],
            destination_port=5060,
            on_con_lost=on_con_lost),
            remote_addr=(sys.argv[1], 5060)
    )

    try:
        while True:
            await protocol.send_loop()
    except KeyboardInterrupt:
        print('Closing the socket')
        transport.close()
    finally:
        transport.close()

asyncio.run(main())



