# 🛡️ ShieldWall AI — Windows Defender Threat Blocker & CLI Suite

An enterprise-grade, real-time security application built with Python and PowerShell. **ShieldWall AI** continuously monitors Windows Security Event Logs for unauthorized connection probes, network scans, and brute-force intrusion attempts, dynamically enforcing persistent inbound block rules directly in **Windows 11 Defender Firewall**.

![Platform](https://img.shields.io/badge/platform-Windows%2011%20%7C%2010-0078D6.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![GUI](https://img.shields.io/badge/GUI-CustomTkinter-darkgreen.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

---

## 🌟 Features

* **Automated Threat Detection**: Monitors Windows Security Event Logs (`Event ID 4625`) for failed authentication attempts, port scans, and remote probes.
* **Direct Firewall Injection**: Automatically injects persistent `Inbound Block Rules` directly into **Windows Defender Firewall with Advanced Security** via administrative PowerShell execution.
* **Modern CustomTkinter GUI**: Dark-mode native desktop interface featuring real-time event logging, active rule tables, status indicators, and one-click unblocking.
* **Embedded PowerShell CLI**: Interactive terminal tab inside the app to execute live network diagnostic commands (`Get-NetTCPConnection`, `Test-NetConnection`, `Get-Process`).
* **Quick Network Tools**: One-click sidebar shortcuts for real-time inspection of active TCP sockets, listening ports, and active IPv4 network interface bindings.
* **Automatic UAC Privilege Elevation**: Automatically prompts for Administrator privileges via Windows User Account Control (UAC) upon launch.

---

## 📂 Repository Structure

```text
windows-firewall-threat-blocker/
├── app.py                                  # Main Python application (GUI & Threat Engine)
├── requirements.txt                        # Application dependencies
├── Application Architecture & Workflow.txt # System design, data flow, and threat model specs
├── README.md                               # Project documentation and quick start guide
├── LICENSE                                 # MIT License
└── .gitignore                              # Git ignore rules
