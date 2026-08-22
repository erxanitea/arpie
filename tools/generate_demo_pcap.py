"""
Generate a synthetic demonstration PCAP with all 4 detection techniques:
  1. ARP Identity Inconsistency
  2. Port-Scan Behavior
  3. Traffic-Rate Anomaly (SYN Burst)
  4. Gateway Identity Change

Output file: sample_pcaps/demo_public_wifi.pcap
"""

import time
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap


def generate_demo_pcap(output_path: str = "sample_pcaps/demo_public_wifi.pcap", gateway_ip: str = "192.168.1.1", victim_ip: str = "192.168.1.100", attacker_ip: str = "192.168.1.50"):
    packets = []
    base_time = time.time() - 60

    print(f"[*] Generating synthetic demo PCAP: {output_path}")

    # Baseline traffic
    pkt_base = Ether() / IP(src=victim_ip, dst=gateway_ip) / TCP(sport=50000, dport=443, flags="PA")
    pkt_base.time = base_time
    packets.append(pkt_base)

    # 1. Technique 2: Port-Scan (>15 ports contacted)
    print("  -> Adding Port-Scan packets...")
    for i, port in enumerate(range(20, 42)):
        p = Ether() / IP(src=attacker_ip, dst=victim_ip) / TCP(sport=40000 + i, dport=port, flags="S")
        p.time = base_time + 10 + (i * 0.1)
        packets.append(p)

    # 2. Technique 1: ARP Identity Inconsistency (2 MACs claiming attacker IP)
    print("  -> Adding ARP Inconsistency packets...")
    arp1 = Ether(src="aa:bb:cc:dd:ee:11", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, hwsrc="aa:bb:cc:dd:ee:11", psrc=attacker_ip,
        hwdst="00:00:00:00:00:00", pdst=victim_ip
    )
    arp1.time = base_time + 20
    packets.append(arp1)

    arp2 = Ether(src="aa:bb:cc:dd:ee:22", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, hwsrc="aa:bb:cc:dd:ee:22", psrc=attacker_ip,
        hwdst="00:00:00:00:00:00", pdst=victim_ip
    )
    arp2.time = base_time + 22
    packets.append(arp2)

    # 3. Technique 3: Traffic Anomaly (burst of SYN packets >100 pps)
    print("  -> Adding Traffic Rate Anomaly burst...")
    for j in range(120):
        syn_flood = Ether() / IP(src=attacker_ip, dst=victim_ip) / TCP(sport=50000 + j, dport=80, flags="S")
        syn_flood.time = base_time + 30 + (j * 0.005)
        packets.append(syn_flood)

    # 4. Technique 4: Gateway Identity Change
    print("  -> Adding Gateway MAC Change packets...")
    gw_mac1 = "00:11:22:33:44:01"
    gw_mac2 = "00:11:22:33:44:02"
    gw1 = Ether(src=gw_mac1, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, hwsrc=gw_mac1, psrc=gateway_ip,
        hwdst="00:00:00:00:00:00", pdst=victim_ip
    )
    gw1.time = base_time + 40
    packets.append(gw1)

    gw2 = Ether(src=gw_mac2, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, hwsrc=gw_mac2, psrc=gateway_ip,
        hwdst="00:00:00:00:00:00", pdst=victim_ip
    )
    gw2.time = base_time + 42
    packets.append(gw2)

    # Ensure output dir exists
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    wrpcap(output_path, packets)
    print(f"[+] Successfully wrote {len(packets)} packets to {output_path}")


if __name__ == "__main__":
    generate_demo_pcap()
