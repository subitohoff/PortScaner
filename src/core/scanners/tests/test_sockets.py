import socket
from time import sleep
import asyncio
from struct import unpack

from core.packet_factory import PacketFactory


async def run():
    src_ip = "127.0.0.1"
    dst_ip = "127.0.0.1"

    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)
    src_port = 1234
    dst_port = 4321
    pf = PacketFactory(src_addr, src_port, dst_addr, dst_port)

    msg = "Here's Johny!".encode("ascii")

    packet = pf.generate_packet(msg)
    sock: socket.socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    # we will provide our own headers
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.bind(("127.0.0.1", src_port))

    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    async def receive():
        print("Listening...")
        while True:
            data, addr = recv_sock.recvfrom(65535)
            if addr[0] != dst_ip:
                continue
            tcp_hdr = data[20:40]
            unpacked = unpack("!HHLLBBHHH", tcp_hdr)
            (
                rcv_src_port,
                rcv_dst_port,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
            ) = unpacked
            if src_port != rcv_src_port or dst_port != rcv_dst_port:
                continue

            recv_msg = data[40:]

            print(f"Got the packet!\nData: {data[40:].decode('ascii')}")

            assert msg == recv_msg

            break

    rcv_task = receive()

    sleep(0.5)
    sock.sendto(packet, (dst_ip, 0))
    print("Packet sent!")
    sock.close()

    await rcv_task

    recv_sock.close()


if __name__ == "__main__":
    asyncio.run(run())
