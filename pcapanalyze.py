import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP, Raw, conf
import sys
import warnings
import argparse
from collections import Counter

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


def pcap_to_csv(pcap_file, csv_file, track_ip=False):
    packets = rdpcap(pcap_file)

    data = []
    ip_counter = Counter()
    ip_requests = {}

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

            # 统计IP频率
            ip_counter[ip_src] += 1
            if ip_src not in ip_requests:
                ip_requests[ip_src] = []
            ip_requests[ip_src].append(packet_info['内容'])

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

    if track_ip:
        most_common_ip, count = ip_counter.most_common(1)[0]
        print(f"\n频率最高的IP地址是: {most_common_ip}，出现了 {count} 次")
        print(f"{most_common_ip} 请求的内容:")
        for content in ip_requests[most_common_ip]:
            print(content)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PCAP分析工具")
    parser.add_argument("pcap_file", help="输入的PCAP文件")
    parser.add_argument("csv_file", help="输出的CSV文件")
    parser.add_argument("-t", "--track_ip", action="store_true", help="提取频率最高的IP并显示其请求的内容")

    args = parser.parse_args()

    pcap_to_csv(args.pcap_file, args.csv_file, args.track_ip)
