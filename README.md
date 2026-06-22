# Intrusion Detection System (IDS) using Data Structures

## Overview

This project is a simplified Intrusion Detection System (IDS) developed in C++ that analyzes network packet data from CSV files and identifies potentially malicious or suspicious network activities.

The project demonstrates the practical application of fundamental Data Structures in Cyber Security by integrating packet processing, threat detection, alert generation, threat ranking, and audit logging into a single system.

---

## Features

* Network packet analysis from CSV datasets
* Detection of suspicious ports
* Detection of suspicious payload keywords
* Large packet anomaly detection
* Threat scoring and risk assessment
* Alert generation and prioritization
* IP-based statistics tracking
* Search alerts by IP address
* Automated report generation

---

## Data Structures Used

### Queue

Used as a packet ingestion buffer to process packets in FIFO order.

### Stack

Maintains an audit log of IDS events and alerts.

### Linked List

Stores generated alerts efficiently.

### Binary Search Tree (BST)

Maintains IP statistics and enables fast lookups.

### Max Heap

Ranks IP addresses according to threat scores.

### Priority Queue

Processes high-risk alerts before lower-priority alerts.

---

## Threat Detection Rules

The IDS generates alerts based on:

### Suspicious Ports

Examples:

* 21 (FTP)
* 22 (SSH)
* 23 (Telnet)
* 445 (SMB)
* 3389 (RDP)
* 3306 (MySQL)
* 8080 (HTTP Alternate)

### Suspicious Keywords

Examples:

* attack
* hack
* malware
* exploit
* password
* admin
* login
* shell

### Large Packets

Packets larger than 1400 bytes are flagged as potentially suspicious.

---

## Project Structure

```text
Intrusion-Detection-System/
│
├── Simplified_IDS_Backend.cpp
├── sample_packets.csv
├── README.md
│
└── ids_output/
    ├── alerts.csv
    ├── ip_statistics.csv
    ├── top_threats.csv
    ├── priority_dispatch.csv
    ├── audit_log.txt
    └── summary.txt
```

---

## Compilation

```bash
g++ -std=c++17 Simplified_IDS_Backend.cpp -o ids_engine
```

---

## Usage

### Analyze a Packet Dataset

```bash
ids_engine packets.csv
```

### Specify Output Directory

```bash
ids_engine packets.csv output_folder
```

### Search Alerts by IP

```bash
ids_engine packets.csv output_folder --search-ip 192.168.1.50
```

### Generate Sample Dataset

```bash
ids_engine --make-sample sample_packets.csv
```

---

## Output Files

### alerts.csv

Contains all generated alerts.

### ip_statistics.csv

Stores statistics and threat scores for each IP address.

### top_threats.csv

Lists the most suspicious IPs ranked by threat score.

### priority_dispatch.csv

Displays alerts ordered by severity.

### audit_log.txt

Maintains a chronological event log.

### summary.txt

Provides an overall analysis report.

---

## Learning Outcomes

This project demonstrates:

* Data Structures implementation
* Network Security concepts
* Intrusion Detection fundamentals
* Threat scoring techniques
* File processing in C++
* Security event management

---

## Technologies Used

* C++
* STL Containers
* CSV Data Processing
* Cyber Security Concepts
* Data Structures and Algorithms

---

## Authors

Anas Imran and Team Members

BS Cyber Security
COMSATS University Islamabad
