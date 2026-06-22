'''
Beacon Detection Script
Author: Stanislav Berdar
Blog: stanberd.com
Description: Analyzes pcap files for beaconing behavior using 
             statistical analysis of connection intervals.
Usage: python capture_analysis.py -f capture.pcap --local-ip x.x.x.x
       python capture_analysis.py (interactive)
'''

from collections import defaultdict
from scapy.all import rdpcap
import statistics, argparse

def cli_args():
    parser = argparse.ArgumentParser(description="Beacon Detection Script. Use with .pcap files.")
    parser.add_argument("--local-ip", help="Local machine IP to be excluded from analysis")
    parser.add_argument("-f", "--file", help="Location of file")
    args = parser.parse_args()

    return args

def file_input():
    args = cli_args()
    if args.file:
        print("Processing Capture. This may take a minute...")
        capture = args.file
        cap = rdpcap(capture)
        return cap

    else:
        while True:
            try:
                capture = input(f"Enter File location: ")
            except KeyboardInterrupt:
                print("\nExiting...")
                exit(1)
            try:
                print("Processing Capture. This may take a minute...")
                cap = rdpcap(capture)
                return cap
            except FileNotFoundError:
                print("\nFile not found. Check name and try again.")
                continue

def parse_cap():
    destIp = defaultdict(list)
    cap = file_input()
    args = cli_args()
    for pkt in cap:
        if pkt.haslayer('TCP') and pkt.haslayer('IP'):
           if pkt["TCP"].flags == 'S' or pkt["TCP"].flags == 'SA':
                if pkt["IP"].dst != args.local_ip:
                    destIp[(pkt["IP"].dst)].append({
                        "Source IP": pkt["IP"].src, 
                        "Timestamp": float(pkt.time)
                        })
    return destIp

def calculate_std():
    result = parse_cap()
    beacons_found = False
    for dest_ip, connections in result.items():
        try:
            timestamps = [conn["Timestamp"] for conn in connections]
            interval = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

            if len(interval) < 2:
                continue

            deviation = statistics.stdev(interval)
            mean = statistics.mean(interval)
            cv = deviation/mean
            if cv < 0.5 and len(timestamps) >=5:
                beacons_found = True
                print(f"--------------------------------")
                print(f"POTENTIAL BEACONING DETECTED")
                print(f"Destination: {dest_ip}")
                print(f"Packet count: {len(timestamps)}")
                print(f"Mean interval: {mean:.2f}s")
                print(f"StDev: {deviation:.2f}")
                print(f"CV: {cv:.2f}")
                print(f"--------------------------------")
        except statistics.StatisticsError as e:
            continue
    if not beacons_found:
        print("No beacons found.")

calculate_std()
