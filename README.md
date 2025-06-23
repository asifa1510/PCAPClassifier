# PCAP Network Attack Detector



Overview

This project detects network attacks (e.g., DDoS, PortScan, Bot) from PCAP files using a pre-trained LightGBM model. It parses PCAPs into CSV format, extracts features like source/destination IP, ports, protocol, and packet length, and classifies traffic as BENIGN or ATTACK. Trained on CICIDS2017, NSL-KDD, and TON_IoT datasets, it supports general and IoT-specific attack detection.

# Features

Parses PCAP files with Scapy, supporting protocols: TCP, UDP, HTTP, DNS, TLS, ARP, ICMP, etc.

Extracts features: source/destination IP, ports, protocol, packet length, timestamp.

Predicts attacks using a pre-trained LightGBM model with encoded IPs and scaled features.

Handles class imbalance with SMOTE during training.

Logs unparsed packets for debugging in ml/unparsed_packets.log.

# Prerequisites

Python 3.8+

# Datasets:

CICIDS2017
NSL-KDD
TON_IoT

Project Structure

# Datasets





CICIDS2017: Labeled traffic with DDoS, PortScan, Bot attacks. Link



NSL-KDD: Classic intrusion detection dataset with 41 features. Link



TON_IoT: IoT-specific dataset with DDoS and other attacks. Link

Citations:





CICIDS2017: Sharafaldin, I., et al. (2018). ICISSP.



NSL-KDD: Tavallaee, M., et al. (2009). IEEE Symposium on Computational Intelligence.



TON_IoT: Moustafa, N. (2021). IEEE DataPort. doi:10.21227/yjtm-6x74

Notes





Ensure PCAP files end with .pcap or .pcapng.



Verify model and preprocessor files exist in ml/ to avoid FileNotFoundError.



Align extracted features with training data formats (e.g., CICIDS2017).



Check ml/unparsed_packets.log for unparsed packet details.



For large PCAPs, monitor memory usage during parsing.

Contributing

Fork the repo, create a branch, and submit a pull request. See CONTRIBUTING.md for details.

License

MIT License

Acknowledgments





Datasets: CICIDS2017, NSL-KDD, TON_IoT



Libraries: Scapy, pandas, LightGBM, scikit-learn
