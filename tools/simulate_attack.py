"""
Live Attack Simulator for Arpie Evaluation & Virtual Lab Demo.

Simulates the 4 exact detection techniques from the IAS2 Project Proposal:
  1. ARP Identity Inconsistency (Multiple MACs claiming same IP)
  2. Port-Scan Behavior (>15 unique destination ports contacted)
  3. Traffic-Rate Anomaly (High PPS SYN / UDP / ICMP burst >100 pkts/s)
  4. Gateway Identity Change (Gateway MAC spoof/flip)
  5. Full Attack Sequence (Demo mode: 1 -> 2 -> 3 -> 4 in sequence)

Usage:
  sudo python tools/simulate_attack.py --target <VICTIM_IP> --gateway <GATEWAY_IP>
"""

import argparse
import sys
import time

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import send, sendp


def simulate_technique_1_arp_spoof(target_ip: str, gateway_ip: str, iface=None):
    """Technique 1: ARP Identity Inconsistency.
    Sends ARP replies with conflicting MAC addresses for the gateway or an IP.
    """
    print(f"\n[*] [Technique 1] Injecting ARP Identity Inconsistency for IP {gateway_ip}...")
    fake_mac_1 = "00:11:22:33:44:aa"
    fake_mac_2 = "00:11:22:33:44:bb"

    # Send 2 conflicting ARP packets
    pkt1 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=gateway_ip, hwsrc=fake_mac_1, pdst=target_ip)
    pkt2 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=gateway_ip, hwsrc=fake_mac_2, pdst=target_ip)

    sendp(pkt1, iface=iface, verbose=False)
    time.sleep(0.5)
    sendp(pkt2, iface=iface, verbose=False)
    print(f"[+] Sent conflicting ARP replies: MACs {fake_mac_1} and {fake_mac_2} claiming {gateway_ip}.")


def simulate_technique_2_port_scan(target_ip: str, start_port: int = 20, count: int = 25, iface=None):
    """Technique 2: Port-Scan Behavior.
    Probes >15 ports from a single source within 10 seconds.
    """
    print(f"\n[*] [Technique 2] Probing {count} destination ports on {target_ip}...")
    for port in range(start_port, start_port + count):
        pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
        send(pkt, iface=iface, verbose=False)
        time.sleep(0.05)
    print(f"[+] Swept ports {start_port} to {start_port + count - 1} against {target_ip}.")


def simulate_technique_3_traffic_anomaly(target_ip: str, packet_count: int = 150, iface=None):
    """Technique 3: Traffic-Rate Anomaly.
    Sends a burst of SYN packets exceeding 100 packets/sec baseline.
    """
    print(f"\n[*] [Technique 3] Sending burst of {packet_count} SYN packets to {target_ip}...")
    packets = [IP(dst=target_ip) / TCP(dport=80, flags="S") for _ in range(packet_count)]
    send(packets, iface=iface, verbose=False)
    print(f"[+] Transmitted {packet_count} SYN packets in rapid burst (>100 pps).")


def simulate_technique_4_gateway_change(gateway_ip: str, target_ip: str, iface=None):
    """Technique 4: Gateway Identity Change.
    Emits gateway MAC changes exceeding threshold within the time window.
    """
    print(f"\n[*] [Technique 4] Simulating Gateway MAC change on {gateway_ip}...")
    rogue_mac_1 = "02:de:ad:be:ef:01"
    rogue_mac_2 = "02:de:ad:be:ef:02"

    pkt1 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=gateway_ip, hwsrc=rogue_mac_1, pdst=target_ip)
    pkt2 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=gateway_ip, hwsrc=rogue_mac_2, pdst=target_ip)

    sendp(pkt1, iface=iface, verbose=False)
    time.sleep(1)
    sendp(pkt2, iface=iface, verbose=False)
    print(f"[+] Gateway {gateway_ip} flipped MAC to {rogue_mac_1} then {rogue_mac_2}.")


def run_full_sequence(target_ip: str, gateway_ip: str, iface=None):
    """Runs a complete 4-stage scripted attack demonstration."""
    print("\n" + "="*60)
    print(f"[*] Starting Full 4-Stage Attack Demo against {target_ip}")
    print("="*60)

    print("\n[Phase 1/4] Reconnaissance - Port Scan Sweep...")
    simulate_technique_2_port_scan(target_ip, start_port=21, count=20, iface=iface)
    time.sleep(2)

    print("\n[Phase 2/4] Layer 2 Inconsistency - ARP Spoofing...")
    simulate_technique_1_arp_spoof(target_ip, gateway_ip, iface=iface)
    time.sleep(2)

    print("\n[Phase 3/4] High Volume Attack - Traffic Rate Anomaly...")
    simulate_technique_3_traffic_anomaly(target_ip, packet_count=130, iface=iface)
    time.sleep(2)

    print("\n[Phase 4/4] Default Route Hijack - Gateway MAC Flip...")
    simulate_technique_4_gateway_change(gateway_ip, target_ip, iface=iface)

    print("\n" + "="*60)
    print("[+] Full attack narrative complete!")
    print("[+] Check Arpie Dashboard: Risk score should climb to CRITICAL (90+).")
    print("[+] You can now click 'Enable Seal Mode' on Arpie to block this host.")
    print("="*60 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Arpie Attack Simulator for IAS2 Project Demo")
    parser.add_argument("--target", help="Victim IP (e.g. Arpie host IP)", default="192.168.56.101")
    parser.add_argument("--gateway", help="Gateway IP to spoof (e.g. 192.168.56.1)", default="192.168.56.1")
    parser.add_argument("--iface", help="Network interface (optional)", default=None)
    args = parser.parse_args()

    while True:
        print("\n" + "="*50)
        print("  ARPIE LIVE ATTACK SIMULATOR (IAS2 DEMO)")
        print("="*50)
        print(f" Target Victim IP : {args.target}")
        print(f" Target Gateway IP: {args.gateway}")
        print("-" * 50)
        print(" [1] Technique 1: ARP Identity Inconsistency")
        print(" [2] Technique 2: Port-Scan Behavior (>15 ports)")
        print(" [3] Technique 3: Traffic-Rate Anomaly (SYN Flood >100 pps)")
        print(" [4] Technique 4: Gateway Identity Change (MAC Flip)")
        print(" [5] Full 4-Stage Attack Narrative (Complete Demo)")
        print(" [0] Exit")
        print("="*50)

        choice = input("Select an option [0-5]: ").strip()
        if choice == "1":
            simulate_technique_1_arp_spoof(args.target, args.gateway, args.iface)
        elif choice == "2":
            simulate_technique_2_port_scan(args.target, iface=args.iface)
        elif choice == "3":
            simulate_technique_3_traffic_anomaly(args.target, iface=args.iface)
        elif choice == "4":
            simulate_technique_4_gateway_change(args.gateway, args.target, args.iface)
        elif choice == "5":
            run_full_sequence(args.target, args.gateway, args.iface)
        elif choice == "0":
            print("Exiting simulator.")
            break
        else:
            print("[!] Invalid option. Please choose 0-5.")


if __name__ == "__main__":
    main()
