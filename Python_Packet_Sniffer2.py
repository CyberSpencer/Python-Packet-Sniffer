# Python_Packet_Sniffer2.py
# Author: Spencer Thomson
# Date: 10/20/2023
# Description: A Python packet sniffer script using Scapy to capture and display IP packet details in a CSV file. 
#              The script also identifies activity on sensitive ports and writes the captured data to a CSV file.
#              Utilizes threading to run the sniffing operation asynchronously and argparse for command-line options.

import argparse  # For command-line options
import scapy.all as scapy  # For packet sniffing
import threading  # To run sniffing in a separate thread
import time  # To track the time
import psutil  # To get active network interface
import socket  # For IP address family constants
import os  # To get the desktop path
import datetime  # To get the current timestamp
import csv  # To write data to a CSV file
from scapy.all import TCP, UDP  # Specific layers to look for in packets

SENSITIVE_PORTS = {22: 'SSH', 23: 'Telnet', 80: 'HTTP', 443: 'HTTPS'}  # Global constant


def get_active_network_interface():
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
                print(f"Active Network Interface: {interface}")
                return interface
    print("No active network interface found.")
    return None


unique_sockets = set()


def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol_num = packet[scapy.IP].proto
        src_port = dst_port = None
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Translate protocol numbers to names
        protocol_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(protocol_num, str(protocol_num))

        if protocol_name == 'TCP' and packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif protocol_name == 'UDP' and packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        port_flag = check_sensitive_port(src_port, dst_port)
        socket_info = (ip_src, src_port, ip_dst, dst_port, protocol_name, timestamp, port_flag)
        unique_sockets.add(socket_info)


def check_sensitive_port(src_port, dst_port):
    port_flag = ''
    if src_port in SENSITIVE_PORTS:
        port_flag = f"{SENSITIVE_PORTS[src_port]} Activity"
    elif dst_port in SENSITIVE_PORTS:
        port_flag = f"{SENSITIVE_PORTS[dst_port]} Activity"
    else:
        port_flag = 'No Sensitive Port Activity'
    return port_flag


def write_to_file():
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    file_path = os.path.join(desktop_path, 'unique_connections.csv')
    with open(file_path, 'w', newline='') as file:
        csv_writer = csv.writer(file)
        csv_writer.writerow(['Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol', 'Timestamp', 'Port Activity'])
        for socket_info in unique_sockets:
            csv_writer.writerow(socket_info)
    print(f"Data written to {file_path}")


def start_sniffing(interface, protocol=None):
    print(f"Starting sniffing on {interface}")
    start_time = time.time()
    try:
        scapy.sniff(iface=interface, prn=packet_callback, store=0, timeout=300)
    except Exception as e:
        print(f"Error: {e}")
    print(f"Stopped sniffing on {interface}")
    print(f"Sniffing duration: {time.time() - start_time} seconds")
    write_to_file()


def main():
    parser = argparse.ArgumentParser(description='Simple Packet Sniffer')
    parser.add_argument('-i', '--interface', help='Specify the network interface', default=get_active_network_interface())
    parser.add_argument('-p', '--protocol', help='Specify the protocol (tcp, udp, icmp)', default=None)
    args = parser.parse_args()

    if args.interface is None:
        return

    sniffing_thread = threading.Thread(target=start_sniffing, args=(args.interface, args.protocol))
    sniffing_thread.start()

    start_time = time.time()

    while sniffing_thread.is_alive():
        time.sleep(60)
        elapsed_time = int((time.time() - start_time) / 60)
        print(f"Sniffing for {elapsed_time} minutes")


if __name__ == "__main__":
    main()
