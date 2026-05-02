# maccdc2012_00010 — Healthcare Network Forensic Analysis

Forensic analysis of a 4,598,557-packet network capture from a multi-subnet healthcare organisation operating across six geographic regions. The repository contains the full written report and a Go-based automated analyser that reproduces all critical findings directly from the pcap.

## Repository Contents

```
├── main.go                        # Go analyser — generates all CA reports from the pcap - takes approximately 20 minutes to execute depending on user specifications
├── Report.pdf                     # Full forensic analysis report
└── README.md
```

## Critical Attacks

| ID | Attack | Attacker | Victim | Key Finding
| CA1 | Unrestricted DNS Zone Transfer | 192.168.202.79 | 192.168.{21,22,23,25,27,28}.25 | All 6 zones returned — complete hostname inventory
| CA2 | FreePBX Authenticated Session & SIP Surveillance | 192.168.202.110 / .76 | 192.168.229.156 | Admin session confirmed pre-capture; SIP SUBSCRIBE accepted
| CA3 | TicketsCAD PHP RFI & Dispatch Record Injection | 192.168.202.102 | 192.168.23.202 | Live dispatch records tampered; config.txt exposed
| CA4 | SMB Null Session & AD Enumeration | 192.168.202.110 / 204.45 | 192.168.28.25 (PA-AD) | IPC$ mounted anonymously; DRSUAPI exposed
| CA5 | Cisco Gateway SSHv1 & SNMP Default Strings | 192.168.202.110 | 192.168.28.254 | SSH session established; DH exchange complete
