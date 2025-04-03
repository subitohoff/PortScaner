from socket import IPPROTO_TCP, htons
from struct import pack, unpack
from dataclasses import dataclass

IP_HDR_LEN = 20
TCP_HDR_BEGIN = 20
TCP_HDR_END = 40


@dataclass
class IPHeader:
    src_addr: bytes
    dst_addr: bytes
    ihl: int = 5
    version: int = 4
    dscp_ecn: int = 0
    tot_len: int = 0  # kernel will do this
    id: int = 0
    frag_off: int = 0
    ttl: int = 255
    proto: int = IPPROTO_TCP
    check: int = 0  # kernel will also do this

    def get_header(self):
        ihl_ver = (self.version << 4) + self.ihl
        return pack(
            "!BBHHHBBH4s4s",
            ihl_ver,
            self.dscp_ecn,
            self.tot_len,
            self.id,
            self.frag_off,
            self.ttl,
            self.proto,
            self.check,
            self.src_addr,
            self.dst_addr,
        )

    @classmethod
    def from_bytes(cls, data):
        (
            ihl_ver,
            dscp_ecn,
            tot_len,
            ident,
            frag_off,
            ttl,
            proto,
            check,
            src_addr,
            dst_addr,
        ) = unpack("!BBHHHBBH4s4s", data)

        version = ihl_ver >> 4
        ihl = ihl_ver & 0x0F

        return cls(
            src_addr=src_addr,
            dst_addr=dst_addr,
            ihl=ihl,
            version=version,
            dscp_ecn=dscp_ecn,
            tot_len=tot_len,
            id=ident,
            frag_off=frag_off,
            ttl=ttl,
            proto=proto,
            check=check,
        )


@dataclass
class TCPHeader:
    src_port: int
    dst_port: int
    seq_num: int = 0
    ack_num: int = 0
    data_off: int = 5  # 4 bit, size of header
    # tcp flags
    tcp_fin: int = 0
    tcp_syn: int = 0
    tcp_rst: int = 0
    tcp_psh: int = 0
    tcp_ack: int = 0
    tcp_urg: int = 0
    tcp_ece: int = 0
    tcp_cwr: int = 0

    window: int = htons(5840)  # maximum allowed window size
    check: int = 0
    urg_ptr: int = 0

    def get_header(self):
        offset_res = self.data_off << 4
        tcp_flags = (
            self.tcp_fin
            + (self.tcp_syn << 1)
            + (self.tcp_rst << 2)
            + (self.tcp_psh << 3)
            + (self.tcp_ack << 4)
            + (self.tcp_urg << 5)
            + (self.tcp_ece << 6)
            + (self.tcp_cwr << 7)
        )
        return pack(
            "!HHLLBBHHH",
            self.src_port,
            self.dst_port,
            self.seq_num,
            self.ack_num,
            offset_res,
            tcp_flags,
            self.window,
            self.check,
            self.urg_ptr,
        )

    @classmethod
    def from_bytes(cls, data):
        (
            src_port,
            dst_port,
            seq_num,
            ack_num,
            offset_res,
            tcp_flags,
            window,
            check,
            urg_ptr,
        ) = unpack("!HHLLBBHHH", data)

        data_off = offset_res >> 4

        return cls(
            src_port=src_port,
            dst_port=dst_port,
            seq_num=seq_num,
            ack_num=ack_num,
            data_off=data_off,
            tcp_fin=tcp_flags & 0x01,
            tcp_syn=(tcp_flags >> 1) & 0x01,
            tcp_rst=(tcp_flags >> 2) & 0x01,
            tcp_psh=(tcp_flags >> 3) & 0x01,
            tcp_ack=(tcp_flags >> 4) & 0x01,
            tcp_urg=(tcp_flags >> 5) & 0x01,
            tcp_ece=(tcp_flags >> 6) & 0x01,
            tcp_cwr=(tcp_flags >> 7) & 0x01,
            window=window,
            check=check,
            urg_ptr=urg_ptr,
        )


def unpack_headers(packet: bytes) -> tuple[IPHeader, TCPHeader]:
    ip_data = packet[:IP_HDR_LEN]
    tcp_data = packet[TCP_HDR_BEGIN:TCP_HDR_END]
    return IPHeader.from_bytes(ip_data), TCPHeader.from_bytes(tcp_data)
