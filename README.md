**PCAP Network Attack Detector**

This project provides an end-to-end machine learning pipeline to detect **network intrusions and attacks** directly from `.pcap` (packet capture) files. It is designed to help automate network forensics by parsing raw network traffic, extracting meaningful features, and classifying it as **BENIGN** or **ATTACK** using a trained **LightGBM** model.

---

**💡 Motivation**

Traditional intrusion detection systems (IDS) often rely on static rule-based engines, which struggle with:
- High false positive rates
- Limited adaptability to new attack patterns
- Inability to analyze large volumes of real-time packet data effectively

This project aims to bridge that gap by using **machine learning** to:
- Automate PCAP parsing and feature extraction
- Detect evolving threats such as **DDoS, Port Scans, Botnet activity**, etc.
- Support both general network and **IoT-specific** attack detection

---

**📚 Datasets Used**

We trained our model on a combination of well-known benchmark datasets:

| Dataset     | Description                                                                 | Link |
|-------------|-----------------------------------------------------------------------------|------|
| **CICIDS2017** | Modern attacks (DDoS, Brute Force, Botnet, PortScan) with rich feature sets | [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) |
| **NSL-KDD**    | Classic IDS dataset with 41 hand-engineered features                       | [NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html) |
| **TON_IoT**    | IoT-specific intrusion dataset covering DoS, ransomware, injection attacks | [TON_IoT](https://ieee-dataport.org/open-access/toniot-datasets) |

---

**⚙️ Project Workflow**

```mermaid
graph LR
A[Raw PCAP File] --> B[Parse Packets with Scapy]
B --> C[Extract Features: IPs, Ports, Protocol, Length, Time]
C --> D[Scale + Encode Features]
D --> E[LightGBM Model]
E --> F[Prediction: BENIGN or ATTACK]
