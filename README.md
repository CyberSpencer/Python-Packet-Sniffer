# Python Packet Sniffer :satellite:

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2C2C2C?style=for-the-badge&logo=scapy&logoColor=white)

This repository contains the `Python_Packet_Sniffer2.py` script, a Python-based packet sniffer tool that leverages Scapy to capture and analyze network packets. The captured packet details are saved in a CSV file on your desktop for further analysis.

### [🎥 YouTube Demonstration](https://www.youtube.com/watch?v=WMmVheaE0xE)

## 🛠️ Technologies and Libraries Used

- **Language:** Python
- **Library:** Scapy
- **Modules:** argparse, threading, time, psutil, socket, os, datetime, csv

## 🎮 How to Run

1. Clone this repository to your local machine.
2. Navigate to the directory containing `Python_Packet_Sniffer2.py`.
3. Run the script by executing the following command in your terminal (use admin/sudo) :
    ```bash
    python Python_Packet_Sniffer2.py
    ```

## 🚀 Features

- Real-time packet capture and analysis.
- Display active network interface.
- Captures IP, TCP, and UDP packets.
- Identifies sensitive port activities.
- Exports packet data to a CSV file.

## 🔄 Program Flow

1. The script begins by identifying the active network interface.
2. It then starts sniffing packets on that interface.
3. As packets are captured, the script checks for any activity on sensitive ports like SSH, Telnet, HTTP, and HTTPS.
4. All unique socket information is saved, and upon completion of sniffing, the data is written to a CSV file on your desktop.

## 🤝 Connect

- **LinkedIn**: [Spencer Thomson](https://www.linkedin.com/in/spencer-thomson-43365b11a/)
- **GitHub**: [CyberSpencer](https://github.com/CyberSpencer)
- **Email**: [spencertsales@gmail.com](mailto:spencertsales@gmail.com)

Feel free to explore the code, and I hope you find this packet sniffer a valuable tool in understanding network analysis and cybersecurity!


## ⚠️ Disclaimer

```diff
- This project is for educational purposes only.
+ Ensure to have the necessary permissions before running network analysis tools.
! Use this tool responsibly.
# Always adhere to ethical hacking guidelines.
@@ Happy Learning and Exploring!@@
