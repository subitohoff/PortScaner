from scapy.all import IP, ICMP, IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, sr1
import time
from core.results import PingStatus

class Pinger:
    def __init__(self, timeout: int = 1):
        self.timeout = timeout
        
    def ping(self, ip_address):
        
        from ipaddress import IPv4Address, IPv6Address
        
        if isinstance(ip_address, IPv4Address):
            return self._ping_ipv4(str(ip_address))
        elif isinstance(ip_address, IPv6Address):
            return self._ping_ipv6(str(ip_address))
        else:
            #jaki typ ip jesi nie znajie to tak moze uratuje 
            ip_str = str(ip_address)
            if ':' in ip_str:  
                return self._ping_ipv6(ip_str)
            else:
                return self._ping_ipv4(ip_str)
    
    def _ping_ipv4(self, ip: str) -> PingStatus:
       
        packet = IP(dst=ip) / ICMP()
        start = time.time()
        reply = sr1(packet, timeout=self.timeout, verbose=0)
        end = time.time()
        
        
        if reply and reply.haslayer(ICMP) and reply[ICMP].type == 0:
            rtt = round((end - start) * 1000, 2)
           # print("aaaaaaaaa")
            return PingStatus(delay_ms=rtt, success=True)
            
        else:
            return PingStatus(delay_ms=0, success=False)
    
    def _ping_ipv6(self, ip: str) -> PingStatus:
       
        packet = IPv6(dst=ip) / ICMPv6EchoRequest()
        start = time.time()
        reply = sr1(packet, timeout=self.timeout, verbose=0)
        end = time.time()
        

        if reply and reply.haslayer(ICMPv6EchoReply):
            rtt = round((end - start) * 1000, 2)
            return PingStatus(delay_ms=rtt, success=True)
        else:
            return PingStatus(delay_ms=0, success=False)
