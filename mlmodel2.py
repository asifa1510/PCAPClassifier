import os
import pandas as pd
import joblib
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ARP, ICMP, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RS, ICMPv6ND_RA, BOOTP, DNS, EAPOL, Raw
from scapy.layers.http import HTTPRequest
from datetime import datetime
import logging
import csv

OUTPUT_DIR = r"C:\pcap\datasets\ml"
os.makedirs(OUTPUT_DIR, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(OUTPUT_DIR, 'unparsed_packets.log'),
    level=logging.INFO,
    format='%(asctime)s - Packet %(packet_no)s - %(message)s'
)

try:
    model = joblib.load(os.path.join(OUTPUT_DIR, 'packet_attack_model_lgb.pkl'))
    le_source_ip = joblib.load(os.path.join(OUTPUT_DIR, 'le_source_ip.pkl'))
    le_dest_ip = joblib.load(os.path.join(OUTPUT_DIR, 'le_dest_ip.pkl'))
    le_protocol = joblib.load(os.path.join(OUTPUT_DIR, 'le_protocol.pkl'))
    scaler = joblib.load(os.path.join(OUTPUT_DIR, 'scaler.pkl'))
    print("Model and preprocessors loaded successfully.")
except FileNotFoundError as e:
    print(f"Error: {e}. Ensure Cell 1 was run to save model and preprocessors in '{OUTPUT_DIR}'.")
    raise

def parse_pcap_to_csv(pcap_file, output_dir):
    if not os.path.exists(pcap_file):
        print(f"File not found: {pcap_file}")
        return None
    base_name = os.path.splitext(os.path.basename(pcap_file))[0]
    output_csv = os.path.join(output_dir, f"{base_name}_parsed.csv")
    try:
        with open(output_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["No.", "Timestamp", "Source", "Dest", "Protocol", "Source Port", "Dest Port", "Length", "Label"])
            with PcapReader(pcap_file) as pcap_reader:
                for i, pkt in enumerate(pcap_reader, 1):
                    src = dst = proto = src_port = dst_port = ""
                    length = len(pkt)
                    label = "UNKNOWN"
                    try:
                        if ARP in pkt:
                            proto = "ARP"
                            src = pkt[ARP].psrc
                            dst = pkt[ARP].pdst
                        elif EAPOL in pkt:
                            proto = "EAPOL"
                            src = pkt.src
                            dst = pkt.dst
                        elif IP in pkt:
                            ip_layer = pkt[IP]
                            src = ip_layer.src
                            dst = ip_layer.dst
                            if TCP in pkt:
                                src_port = pkt[TCP].sport
                                dst_port = pkt[TCP].dport
                                if HTTPRequest in pkt and dst_port in [80, 8080]:
                                    proto = "HTTP"
                                elif dst_port == 443 and Raw in pkt:
                                    try:
                                        payload = pkt[Raw].load
                                        if len(payload) >= 5 and payload[0] == 0x16 and payload[1:3] == b"\x03\x03":
                                            proto = "TLSv1.2"
                                        else:
                                            proto = "TCP"
                                    except:
                                        proto = "TCP"
                                else:
                                    proto = "TCP"
                            elif UDP in pkt:
                                src_port = pkt[UDP].sport
                                dst_port = pkt[UDP].dport
                                if DNS in pkt and (src_port == 53 or dst_port == 53):
                                    proto = "DNS"
                                elif BOOTP in pkt and (src_port == 68 or dst_port == 67):
                                    proto = "DHCP"
                                elif dst_port == 5353 or dst in ["224.0.0.251", "ff02::fb"]:
                                    proto = "mDNS"
                                elif src_port == 123 or dst_port == 123:
                                    proto = "NTP"
                                elif src_port == 69 or dst_port == 69:
                                    proto = "TFTP"
                                elif src_port == 161 or dst_port == 161:
                                    proto = "SNMP"
                                else:
                                    proto = "UDP"
                            elif ICMP in pkt:
                                proto = "ICMP"
                            elif ip_layer.proto == 2:
                                proto = "IGMP"
                                if pkt.haslayer("IGMP") and hasattr(pkt.getlayer("IGMP"), "gaddr"):
                                    proto = "IGMPv3"
                            else:
                                proto = str(ip_layer.proto)
                        elif IPv6 in pkt:
                            ip_layer = pkt[IPv6]
                            src = ip_layer.src
                            dst = ip_layer.dst
                            if ICMPv6ND_NS in pkt or ICMPv6ND_NA in pkt or ICMPv6ND_RS in pkt or ICMPv6ND_RA in pkt:
                                proto = "ICMPv6"
                            elif TCP in pkt:
                                src_port = pkt[TCP].sport
                                dst_port = pkt[TCP].dport
                                if dst_port == 443 and Raw in pkt:
                                    try:
                                        payload = pkt[Raw].load
                                        if len(payload) >= 5 and payload[0] == 0x16 and payload[1:3] == b"\x03\x03":
                                            proto = "TLSv1.2"
                                        else:
                                            proto = "TCP"
                                    except:
                                        proto = "TCP"
                                else:
                                    proto = "TCP"
                            elif UDP in pkt:
                                src_port = pkt[UDP].sport
                                dst_port = pkt[UDP].dport
                                if DNS in pkt and (src_port == 53 or dst_port == 53):
                                    proto = "DNS"
                                elif BOOTP in pkt and (src_port == 546 or dst_port == 547):
                                    proto = "DHCPv6"
                                elif dst_port == 5353 or dst == "ff02::fb":
                                    proto = "mDNS"
                                elif src_port == 123 or dst_port == 123:
                                    proto = "NTP"
                                elif src_port == 69 or dst_port == 69:
                                    proto = "TFTP"
                                elif src_port == 161 or dst_port == 161:
                                    proto = "SNMP"
                                else:
                                    proto = "UDP"
                            else:
                                proto = "IPv6"
                        else:
                            proto = "UNKNOWN"
                            layers = [layer.__class__.__name__ for layer in pkt]
                            logging.info(f"Unparsed packet: Layers={layers}, Summary={pkt.summary()}", extra={'packet_no': i})
                        timestamp = datetime.fromtimestamp(float(pkt.time)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                        writer.writerow([i, timestamp, src, dst, proto, src_port, dst_port, length, label])
                    except Exception as e:
                        logging.error(f"Error parsing packet: {str(e)}, Summary={pkt.summary()}", extra={'packet_no': i})
        print(f"Parsed PCAP to {output_csv}")
        return output_csv
    except Exception as e:
        print(f"Error parsing PCAP: {str(e)}")
        return None

def predict_on_csv(csv_file, output_dir):
    try:
        new_data = pd.read_csv(csv_file)
        new_data.columns = new_data.columns.str.strip().str.lower().str.replace(' ', '_')
        new_data = new_data.rename(columns={
            'source': 'source_ip',
            'dest': 'destination_ip',
            'protocol': 'protocol',
            'source_port': 'source_port',
            'dest_port': 'destination_port',
            'length': 'packet_length',
            'label': 'label'
        })
        new_data = new_data.fillna({
            'source_ip': '0.0.0.0',
            'destination_ip': '0.0.0.0',
            'protocol': 'UNKNOWN',
            'source_port': 0,
            'destination_port': 0,
            'packet_length': 0,
            'timestamp': '1970-01-01 00:00:00'
        })
        new_data['timestamp'] = pd.to_datetime(new_data['timestamp'], errors='coerce')
        new_data['hour'] = new_data['timestamp'].dt.hour.fillna(0).astype(int)
        new_data['minute'] = new_data['timestamp'].dt.minute.fillna(0).astype(int)
        new_data['second'] = new_data['timestamp'].dt.second.fillna(0).astype(int)
        new_data['source_ip_encoded'] = new_data['source_ip'].apply(
            lambda x: le_source_ip.transform([x])[0] if x in le_source_ip.classes_ else -1
        )
        new_data['destination_ip_encoded'] = new_data['destination_ip'].apply(
            lambda x: le_dest_ip.transform([x])[0] if x in le_dest_ip.classes_ else -1
        )
        new_data['protocol_encoded'] = new_data['protocol'].apply(
            lambda x: le_protocol.transform([x])[0] if x in le_protocol.classes_ else -1
        )
        features = ['source_ip_encoded', 'destination_ip_encoded', 'protocol_encoded',
                    'source_port', 'destination_port', 'packet_length', 'hour', 'minute', 'second']
        X_new = new_data[features].copy()
        X_new.loc[:, ['source_port', 'destination_port', 'packet_length', 'hour', 'minute', 'second']] = scaler.transform(
            X_new[['source_port', 'destination_port', 'packet_length', 'hour', 'minute', 'second']]
        )
        predictions = model.predict(X_new)
        new_data['prediction'] = ['BENIGN' if p == 0 else 'ATTACK' for p in predictions]
        base_name = os.path.splitext(os.path.basename(csv_file))[0]
        output_file = os.path.join(output_dir, f"{base_name}_predicted.csv")
        new_data.to_csv(output_file, index=False)
        print(f"Predictions saved to {output_file}")
        print("\nPrediction Summary:")
        print(new_data['prediction'].value_counts())
        return new_data
    except Exception as e:
        print(f"Error predicting on CSV: {str(e)}")
        return None

pcap_file = r"\\wsl.localhost\Ubuntu\home\asifa\capture.pcap"
if os.path.exists(pcap_file) and pcap_file.lower().endswith(('.pcap', '.pcapng')):
    csv_file = parse_pcap_to_csv(pcap_file, OUTPUT_DIR)
    if csv_file:
        predicted_data = predict_on_csv(csv_file, OUTPUT_DIR)
        if predicted_data is not None:
            print("Prediction complete")
else:
    print(r"Invalid PCAP path")
