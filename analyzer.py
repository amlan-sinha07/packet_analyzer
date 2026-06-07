from scapy.all import sniff,IP ,TCP ,UDP,ICMP
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
            service=self._get_service(packet)
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
            "service":service,
            "count":self.ip_counter[src]
        }
        self.packet_log.append(entry)
        self.packet_captured+=1
        print(f"[{timestamp}] {service} | {src} -> {dst}")
    def get_top_ips(self,n=5):
        sorted_ips=sorted(self.ip_counter.items(),key=lambda x : x[1], reverse=True)
        return sorted_ips
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
    def _get_service(self,packet):
        services={
            80:"HTTP",
            443:"HTTPS",
            53:"DNS",
            22:"SSH",
            25:"SMTP",
            3306:"MySQL",
            8080:"HTTP-ALT"
        }
        if packet.haslayer(TCP):
            port=packet[TCP].dport
            return services.get(port,f"TCP: {port}")
        elif packet.haslayer(UDP):
            port=packet[UDP].dport
            return services.get(port,f"UDP: {port}")
        return "OTHER"
    def get_protocol_breakdown(self):
        counts={"TCP":0,"UDP":0,"OTHERS":0}
        for entry in self.packet_log:
            protocol=entry["protocol"]
            if protocol in counts:
                counts[protocol]+=1
            else:
                counts["OTHERS"]+=1
        total=self.packet_captured
        breakdown={}
        for proto,count in counts.items():
            if total>0:
                breakdown[proto]=round((count/total)*100,1)
        return breakdown