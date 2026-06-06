from scapy.all import sniff,IP ,TCP ,UDP,ICMP
from scapy.all import IP
from datetime import datetime

class PacketAnalyzer:
    def __init__(self):
        self.packet_captured=0
        self.ip_counter={}
        self.packet_log=[]
        self.suspicious_ip=[]
        self.threshold=10
    def process_packet(self,packet):
        if not packet.haslayer(IP):
            return
        timestamp=datetime.now().strftime("%H:%M:%S")
        if packet.haslayer(IP):
            src=packet[IP].src
            dst=packet[IP].dst
            protocol=self._get_protocol(packet)
            if src in self.ip_counter:
                self.ip_counter[src]+=1
            else:
                self.ip_counter[src]=1
            if self.ip_counter[src]>=self.threshold:
                if src not in self.suspicious_ip:
                    self.suspicious_ip.append(src)
                    print(f"suspicious ip: {src} ({self.ip_counter[src]}) packets")
        entry={
            "time":timestamp,
            "src":src,
            "dst":dst,
            "protocol":protocol,
            "count":self.ip_counter[src]
        }
        self.packet_log.append(entry)
        self.packet_captured+=1
        print(f"[{timestamp}] {protocol} | {src} -> {dst}")
    def _get_protocol(self,packet):
        if packet.haslayer(TCP):
            return "TCP"
        elif packet.haslayer(UDP):
            return "UDP"
        elif packet.haslayer(ICMP):
            return "ICMP"
        else:
            return "others"
    def get_stats(self):
        return {
            "total":self.packet_captured,
            "unique_ips": len(self.ip_counter),
            "suspicious": len(self.suspicious_ip),
            "top_ip":max(self.ip_counter,key=self.ip_counter.get) if self.ip_counter else "None",

        }
    def start_capture(self,count=20):
        print(f"starting capture... ({count} packets)")
        print("-"*50)
        try:
            sniff(prn=self.process_packet,count=count)
        except PermissionError:
            print("run as administrator!")
        except Exception as e:
            print(f"error: {e}")