from scapy.all import sniff, IP, TCP
import logging
import datetime #logging was ugly without it


# make logging work (configure it to log to a file)
logging.basicConfig(filename='firewall.log', level=logging.INFO)

# make the lists to hold blocked IP's and ports
blocked_ips = ["192.168.1.1", "10.0.0.2"]
blocked_ports = [22, 443]

# make a list of test packets to simulate the firewall logic
test_packets = [
    IP(src="192.168.1.1"),  # Should be blocked
    IP(src="10.0.0.5"),  # Should be allowed
    IP(dst="10.0.0.8") / TCP(dport=443),  # Should be blocked
    IP(dst="10.0.0.8") / TCP(dport=8080)  # Should be allowed
]

# define the logging function to call in other functions (makes sense)
def log_blocked_packet(packet):
    if packet.haslayer(TCP):
        timestamp = datetime.datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
        logging.info(f"Blocked packet from {packet[IP].src} to port {packet[TCP].dport} at {timestamp}")


# Firewall function to sniff/monitor packets flowing into my machine/network
def capture_packets(packet):

    # Print the packet summary
    print(packet.summary())
    
    sniff(filter='ip and port', prn=capture_packets)

# function to filter packets based on blocked source IPs and destination ports
def filter_packet(packet):

    # check blocked ip's
    if packet.haslayer('IP') and packet['IP'].src in blocked_ips:
        print(f"Blocked IP: {packet['IP'].src}")
        log_blocked_packet(packet)
        return False # this will drop the packet

    # check blocked ports
    if packet.haslayer('TCP') and packet['TCP'].dport in blocked_ports:
        print(f"Blocked Port: {packet['TCP'].dport}")
        log_blocked_packet(packet)
        return False
    
    return True # allow all other packets

#function to allow me to simulate this without messing with my actual firewall
def simulate_packets():
    print("Simulating packets...")
    for pkt in test_packets:
        filter_packet(pkt)


#sniff(filter="ip and port", prn=lambda pkt: filter_packet(pkt)) #starts the sniffing

def main():
    
    simulate_packets() # running the simulation function to test the firewall logic

main() # run the main function to start the program