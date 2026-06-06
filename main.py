from analyzer import PacketAnalyzer
from reporter import Reporter
def main():
    print("="*50)
    analyzer=PacketAnalyzer()
    reporter=Reporter()
    try:
        count=int(input("\nhow many packets to capture? (default 20)=" or "20"))
        threshold=int(input("\nsuspicious ip thresold? (default 10)=" or "10"))
        analyzer.threshold=threshold
    except ValueError:
        print("invalid input- using defaults")
        count=20
    print("\n")
    analyzer.start_capture(count=count)
    stats=analyzer.get_stats()
    print("\n"+"="*50)
    print("CAPTURE COMPLETE")
    print("="*50)
    print(f"total packets:  {stats['total']}")
    print(f"unique ip:  {stats['unique_ips']}")
    print(f"suspicious ip:  {stats['suspicious']}")
    print(f"top talker: {stats['top_ip']}")
    save=input("\nsave report? (y/n): ")
    if save.lower()=="y":
        reporter.save_reports(
            stats,
            analyzer.ip_counter,
            analyzer.suspicious_ip,
            analyzer.packet_log
        )
        print("\ndone")
if __name__=="__main__":
    main()