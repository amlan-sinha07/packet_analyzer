from datetime import datetime
import os

class Reporter:
    def __init__(self,reports_folders="reports"):
        self.reports_folders=reports_folders
        if not os.path.exists(reports_folders):
            os.makedirs(reports_folders)
    def save_reports(self,stats,ip_counter,suspicious_ip,packet_log):
        timestamp=datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename=f"{self.reports_folders}/report_{timestamp}"
        with open(filename,"w",encoding="utf-8") as f:
            f.write("="*50+"\n")
            f.write("NETWORK PACKET ANALYSIS REPORT\n")
            f.write("="*50+"\n\n")
            f.write(f"generated:    {timestamp}\n")
            f.write(f"total packets:{stats['total']}\n")
            f.write(f"unique ip:    {stats['unique_ips']}\n")
            f.write(f"top ip:       {stats['top_ip']}\n\n")
            f.write(f"-----IP TAFFIC-----\n")
            for ip,count in sorted(ip_counter.items(),key=lambda x:x[1],reverse=True):
                f.write(f"{ip} -> {count} packet\n")
            f.write(f"-----SUSPICIOUS IP-----\n\n")
            if suspicious_ip:
                for ip in suspicious_ip:
                    f.write(f"⚠️ {ip}\n")
            else:
                f.write("none detected\n")
        print(f"\n report saved {filename}")
        return filename