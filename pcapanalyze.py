import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP, Raw, conf
import sys
import warnings

# 忽略 Scapy 的警告
conf.verb = 0

# 忽略所有警告
warnings.filterwarnings("ignore")


def hex_to_ascii(hex_str):
    try:
        bytes_obj = bytes.fromhex(hex_str)
        return bytes_obj.decode('ascii', errors='replace')
    except Exception as e:
        return hex_str


def pcap_to_csv(pcap_file, csv_file):
    packets = rdpcap(pcap_file)

    data = []

    for packet in packets:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto
            length = packet[IP].len
            packet_info = {
                '源IP': ip_src,
                '目标IP': ip_dst,
                '协议': proto,
                '长度': length
            }

            if TCP in packet:
                packet_info['源端口'] = packet[TCP].sport
                packet_info['目标端口'] = packet[TCP].dport
                packet_info['标志'] = packet[TCP].flags
                if Raw in packet:
                    raw_data = packet[Raw].load.hex()
                    readable_content = hex_to_ascii(raw_data)
                    packet_info['内容'] = readable_content
                else:
                    packet_info['内容'] = '无'
            elif UDP in packet:
                packet_info['源端口'] = packet[UDP].sport
                packet_info['目标端口'] = packet[UDP].dport
                if Raw in packet:
                    raw_data = packet[Raw].load.hex()
                    readable_content = hex_to_ascii(raw_data)
                    packet_info['内容'] = readable_content
                else:
                    packet_info['内容'] = '无'
            else:
                packet_info['内容'] = '无'

            data.append(packet_info)

            proto_name = 'TCP' if proto == 6 else 'UDP' if proto == 17 else '其他'
            print(f"{ip_src} 向 {ip_dst} 发送了 {proto_name} 数据包，内容: {packet_info['内容']}")

    df = pd.DataFrame(data)
    df.to_csv(csv_file, index=False)

    print(f"\n总数据包数: {len(packets)}")
    print(f"总IP数据包数: {len(df)}")
    print("协议分布:")
    for proto, count in df['协议'].value_counts().items():
        proto_name = 'TCP' if proto == 6 else 'UDP' if proto == 17 else '其他'
        print(f"  {proto_name} ({proto}): {count}")

    print("前五个源IP地址:")
    print(df['源IP'].value_counts().head())

    print("前五个目标IP地址:")
    print(df['目标IP'].value_counts().head())

    if '源端口' in df.columns:
        print("前五个源端口:")
        print(df['源端口'].value_counts().head())

    if '目标端口' in df.columns:
        print("前五个目标端口:")
        print(df['目标端口'].value_counts().head())


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("用法: python3 pcapanalyze.py <输入_pcap_文件> <输出_csv_文件>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    csv_file = sys.argv[2]

    pcap_to_csv(pcap_file, csv_file)