import os
import csv
import logging
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ARP, ICMP, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RS, ICMPv6ND_RA, BOOTP, DNS, EAPOL, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse

from datetime import datetime
from collections import defaultdict

logging.basicConfig(
    filename='unparsed_packets.log',
    level=logging.INFO,
    format='%(asctime)s - Packet %(packet_no)s - %(message)s'
)

def parse_pcap(pcap_file):
    if not os.path.exists(pcap_file):
        print(f"File not found: {pcap_file}")
        return

    output_csv = os.path.splitext(pcap_file)[0] + "_parsed_with_attacks.csv"

    syn_counts = defaultdict(int)
    port_scan_tracker = defaultdict(set)
    icmp_counts = defaultdict(int)
    icmpv6_counts = defaultdict(int)
    udp_counts = defaultdict(int)
    arp_mac_tracker = defaultdict(list)
    dhcp_counts = defaultdict(int)
    mdns_counts = defaultdict(int)
    eapol_counts = defaultdict(int)
    igmp_counts = defaultdict(int)
    http_counts = defaultdict(int)
    dns_counts = defaultdict(int)
    tls_counts = defaultdict(int)
    generic_counts = defaultdict(int)  

    SYN_FLOOD_THRESHOLD = 50
    PORT_SCAN_PORTS_THRESHOLD = 10
    ICMP_THRESHOLD = 100
    ICMPv6_THRESHOLD = 100
    UDP_THRESHOLD = 50
    DHCP_THRESHOLD = 50
    MDNS_THRESHOLD = 50
    EAPOL_THRESHOLD = 20
    IGMP_THRESHOLD = 50
    HTTP_THRESHOLD = 100
    DNS_THRESHOLD = 50
    DNS_AMP_SIZE = 500
    TLS_THRESHOLD = 50
    GENERIC_THRESHOLD = 100  

    try:
        with open(output_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["No.", "Timestamp", "Source", "Dest", "Protocol", "Source Port", "Dest Port", "Length", "Classification"])

            with PcapReader(pcap_file) as pcap_reader:
                for i, pkt in enumerate(pcap_reader, start=1):
                    src = dst = proto = src_port = dst_port = ""
                    length = len(pkt)
                    classification = "BENIGN"
                    attack_type = None

                    try:
                        if ARP in pkt:
                            proto = "ARP"
                            src = pkt[ARP].psrc
                            dst = pkt[ARP].pdst
                            arp_mac_tracker[src].append((pkt[ARP].hwsrc, pkt.time))
                            if len(set(mac for mac, _ in arp_mac_tracker[src])) > 1:
                                classification = "ATTACK (ARP Spoofing)"
                                attack_type = "ARP Spoofing"

                        elif EAPOL in pkt:
                            proto = "EAPOL"
                            src = pkt.src
                            dst = pkt.dst
                            eapol_counts[pkt.src] += 1
                            if eapol_counts[pkt.src] > EAPOL_THRESHOLD:
                                classification = "ATTACK (EAPOL Flood)"
                                attack_type = "EAPOL Flood"

                        elif IP in pkt:
                            ip_layer = pkt[IP]
                            src = ip_layer.src
                            dst = ip_layer.dst

                            if TCP in pkt:
                                src_port = pkt[TCP].sport
                                dst_port = pkt[TCP].dport
                                key = (src, dst, dst_port)

                                if HTTPRequest in pkt and dst_port in [80, 8080]:
                                    proto = "HTTP"
                                    http_counts[key] += 1
                                    if http_counts[key] > HTTP_THRESHOLD:
                                        classification = "ATTACK (HTTP Flood)"
                                        attack_type = "HTTP Flood"
                                    method = pkt[HTTPRequest].Method.decode() if pkt[HTTPRequest].Method else ""
                                    if method in ["TRACE", "CONNECT"]:
                                        classification = "ATTACK (Suspicious HTTP Method)"
                                        attack_type = "Suspicious HTTP Method"

                                elif dst_port == 443 and Raw in pkt:
                                    try:
                                        payload = pkt[Raw].load
                                        if len(payload) >= 5 and payload[0] == 0x16 and payload[1:3] == b"\x03\x03":
                                            proto = "TLSv1.2"
                                            tls_counts[key] += 1
                                            if tls_counts[key] > TLS_THRESHOLD:
                                                classification = "ATTACK (TLS Flood)"
                                                attack_type = "TLS Flood"
                                            if len(payload) < 10:
                                                classification = "ATTACK (Malformed TLS)"
                                                attack_type = "Malformed TLS"
                                        else:
                                            proto = "TCP"
                                    except (IndexError, AttributeError):
                                        proto = "TCP"

                                else:
                                    proto = "TCP"
                                    if pkt[TCP].flags == "S":
                                        syn_counts[key] += 1
                                        port_scan_tracker[src].add((dst, dst_port))
                                        if syn_counts[key] > SYN_FLOOD_THRESHOLD:
                                            classification = "ATTACK (SYN Flood)"
                                            attack_type = "SYN Flood"
                                        elif len(port_scan_tracker[src]) > PORT_SCAN_PORTS_THRESHOLD:
                                            classification = "ATTACK (Port Scan)"
                                            attack_type = "Port Scan"

                            elif UDP in pkt:
                                src_port = pkt[UDP].sport
                                dst_port = pkt[UDP].dport
                                key = (src, dst, dst_port)

                                if DNS in pkt and (src_port == 53 or dst_port == 53):
                                    proto = "DNS"
                                    dns_counts[src] += 1
                                    if dns_counts[src] > DNS_THRESHOLD:
                                        classification = "ATTACK (DNS Flood)"
                                        attack_type = "DNS Flood"
                                    if len(pkt) > DNS_AMP_SIZE and pkt[DNS].qr == 1:
                                        classification = "ATTACK (DNS Amplification)"
                                        attack_type = "DNS Amplification"

                                elif BOOTP in pkt and (src_port == 68 or dst_port == 67):
                                    proto = "DHCP"
                                    dhcp_counts[src] += 1
                                    if dhcp_counts[src] > DHCP_THRESHOLD:
                                        classification = "ATTACK (DHCP Starvation)"
                                        attack_type = "DHCP Starvation"
                                    if pkt[BOOTP].op == 2 and src not in ["192.168.0.1", "10.0.0.1"]:
                                        classification = "ATTACK (DHCP Spoofing)"
                                        attack_type = "DHCP Spoofing"

                                elif dst_port == 5353 or dst in ["224.0.0.251", "ff02::fb"]:
                                    proto = "mDNS"
                                    mdns_counts[src] += 1
                                    if mdns_counts[src] > MDNS_THRESHOLD:
                                        classification = "ATTACK (mDNS Flood)"
                                        attack_type = "mDNS Flood"

                                else:
                                    proto = "UDP"
                                    udp_counts[key] += 1
                                    if src_port == 123 or dst_port == 123:
                                        proto = "NTP"
                                    if udp_counts[key] > UDP_THRESHOLD:
                                        classification = "ATTACK (UDP Flood)"
                                        attack_type = "UDP Flood"

                            elif ICMP in pkt:
                                proto = "ICMP"
                                icmp_counts[src] += 1
                                if icmp_counts[src] > ICMP_THRESHOLD:
                                    classification = "ATTACK (ICMP Flood)"
                                    attack_type = "ICMP Flood"

                            elif ip_layer.proto == 2:
                                proto = "IGMP"
                                if pkt.haslayer("IGMP") and hasattr(pkt.getlayer("IGMP"), "gaddr") and pkt.getlayer("IGMP").gaddr:
                                    proto = "IGMPv3"
                                igmp_counts[src] += 1
                                if igmp_counts[src] > IGMP_THRESHOLD:
                                    classification = "ATTACK (IGMP Flood)"
                                    attack_type = "IGMP Flood"

                            else:
                                proto = str(ip_layer.proto)
                                generic_counts[(src, proto)] += 1
                                if generic_counts[(src, proto)] > GENERIC_THRESHOLD:
                                    classification = "ATTACK (Generic Flood)"
                                    attack_type = "Generic Flood"

                        elif IPv6 in pkt:
                            ip_layer = pkt[IPv6]
                            src = ip_layer.src
                            dst = ip_layer.dst

                            if ICMPv6ND_NS in pkt or ICMPv6ND_NA in pkt or ICMPv6ND_RS in pkt or ICMPv6ND_RA in pkt:
                                proto = "ICMPv6"
                                icmpv6_counts[src] += 1
                                if icmpv6_counts[src] > ICMPv6_THRESHOLD:
                                    classification = "ATTACK (ICMPv6 Flood)"
                                    attack_type = "ICMPv6 Flood"

                            elif TCP in pkt:
                                src_port = pkt[TCP].sport
                                dst_port = pkt[TCP].dport
                                key = (src, dst, dst_port)

                                if dst_port == 443 and Raw in pkt:
                                    try:
                                        payload = pkt[Raw].load
                                        if len(payload) >= 5 and payload[0] == 0x16 and payload[1:3] == b"\x03\x03":
                                            proto = "TLSv1.2"
                                            tls_counts[key] += 1
                                            if tls_counts[key] > TLS_THRESHOLD:
                                                classification = "ATTACK (TLS Flood)"
                                                attack_type = "TLS Flood"
                                            if len(payload) < 10:
                                                classification = "ATTACK (Malformed TLS)"
                                                attack_type = "Malformed TLS"
                                        else:
                                            proto = "TCP"
                                    except (IndexError, AttributeError):
                                        proto = "TCP"

                                else:
                                    proto = "TCP"
                                    if pkt[TCP].flags == "S":
                                        syn_counts[key] += 1
                                        port_scan_tracker[src].add((dst, dst_port))
                                        if syn_counts[key] > SYN_FLOOD_THRESHOLD:
                                            classification = "ATTACK (SYN Flood)"
                                            attack_type = "SYN Flood"
                                        elif len(port_scan_tracker[src]) > PORT_SCAN_PORTS_THRESHOLD:
                                            classification = "ATTACK (Port Scan)"
                                            attack_type = "Port Scan"

                            elif UDP in pkt:
                                src_port = pkt[UDP].sport
                                dst_port = pkt[UDP].dport
                                key = (src, dst, dst_port)

                                if DNS in pkt and (src_port == 53 or dst_port == 53):
                                    proto = "DNS"
                                    dns_counts[src] += 1
                                    if dns_counts[src] > DNS_THRESHOLD:
                                        classification = "ATTACK (DNS Flood)"
                                        attack_type = "DNS Flood"
                                    if len(pkt) > DNS_AMP_SIZE and pkt[DNS].qr == 1:
                                        classification = "ATTACK (DNS Amplification)"
                                        attack_type = "DNS Amplification"

                                elif BOOTP in pkt and (src_port == 546 or dst_port == 547):
                                    proto = "DHCPv6"
                                    dhcp_counts[src] += 1
                                    if dhcp_counts[src] > DHCP_THRESHOLD:
                                        classification = "ATTACK (DHCPv6 Starvation)"
                                        attack_type = "DHCPv6 Starvation"

                                elif dst_port == 5353 or dst == "ff02::fb":
                                    proto = "mDNS"
                                    mdns_counts[src] += 1
                                    if mdns_counts[src] > MDNS_THRESHOLD:
                                        classification = "ATTACK (mDNS Flood)"
                                        attack_type = "mDNS Flood"

                                else:
                                    proto = "UDP"
                                    udp_counts[key] += 1
                                    if src_port == 123 or dst_port == 123:
                                        proto = "NTP"
                                    if udp_counts[key] > UDP_THRESHOLD:
                                        classification = "ATTACK (UDP Flood)"
                                        attack_type = "UDP Flood"

                            else:
                                proto = "IPv6"
                                generic_counts[(src, proto)] += 1
                                if generic_counts[(src, proto)] > GENERIC_THRESHOLD:
                                    classification = "ATTACK (Generic Flood)"
                                    attack_type = "Generic Flood"

                        else:
                            proto = "UNKNOWN"
                            layers = [layer.__class__.__name__ for layer in pkt]
                            logging.info(f"Unparsed packet: Layers={layers}, Summary={pkt.summary()}", extra={'packet_no': i})
                            generic_counts[(src, proto)] += 1
                            if generic_counts[(src, proto)] > GENERIC_THRESHOLD:
                                classification = "ATTACK (Generic Flood)"
                                attack_type = "Generic Flood"

                    except Exception as e:
                        logging.error(f"Error parsing packet: {str(e)}, Summary={pkt.summary()}", extra={'packet_no': i})
                        proto = "ERROR"
                        classification = "BENIGN"

                    timestamp = datetime.fromtimestamp(float(pkt.time)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

                    writer.writerow([
                        i,
                        timestamp,
                        src,
                        dst,
                        proto,
                        src_port,
                        dst_port,
                        length,
                        classification
                    ])

        print(f"Done! CSV saved at: {output_csv}")
        print(f"Unparsed packets logged at: unparsed_packets.log")

    except PermissionError:
        print(f"Permission denied: Unable to write to {output_csv}. Try running as administrator or use a different directory.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    pcap_path = input("Enter full path to your .pcap or .pcapng file: ").strip()
    if os.path.exists(pcap_path) and pcap_path.lower().endswith((".pcap", ".pcapng")):
        parse_pcap(pcap_path)
    else:
        print("Invalid file path or file is not a .pcap or .pcapng file.")
