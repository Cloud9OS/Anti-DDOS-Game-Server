import pyshark
import time
import os
import psutil
import requests
from multiprocessing import Pool

# Function to read IP addresses from a file
def read_ip_addresses(filename):
    with open(filename, 'r') as file:
        return {line.strip() for line in file}

# Function to read flagged IP addresses from a file
def read_flagged_ips(filename):
    if not os.path.exists(filename):
        return set()
    with open(filename, 'r') as file:
        return {line.strip() for line in file}

# Function to write flagged IP addresses to a file
def write_flagged_ip(filename, ip):
    with open(filename, 'a') as file:
        file.write(ip + '\n')

# Function to send notification to Discord webhook
def send_discord_notification(protocol_type, current_rate):
    webhook_url = 'Your_Discord_webhook'
    message = {
        "content": "Attack Detected!",
        "embeds": [
            {
                "title": "Attack Detected",
                "description": f"**Attack Type:** {protocol_type}\n**Megabits/s:** {current_rate:.2f}",
                "footer": {"text": "Coded By Rectofen"},
                "color": 16711680,  # Red color
                "image": {
                    "url": "https://cdn.discordapp.com/attachments/1162179717097599108/1211563441123369041/image0.jpg?ex=65eea762&is=65dc3262&hm=e55f515fb70079ed38bd462d1d43ccedcffecb5ac74bcf4ebc7d838dd7cead58&"
                }
            }
        ]
    }
    requests.post(webhook_url, json=message)

# Function to sniff UDP traffic on port 7787
def sniff_udp_traffic():
    capture = pyshark.LiveCapture(interface=r'\Device\NPF_{98C222B3-D30F-40B9-9CC1-57DAB997E3A0}', bpf_filter='udp port 7787')
    return capture.sniff_continuously()

# Function to check if an IP address is in the list
def is_ip_in_list(ip, ip_list):
    return ip in ip_list

# Function to process packets and flag IP addresses
def process_packet(args):
    packet, ip_list, flagged_ips, total_data_received, start_time, last_bytes_received = args
    try:
        ip_src = packet.ip.src
        protocol_type = None
        
        # Identify the protocol type
        if packet.transport_layer == 'UDP':
            if packet.udp.srcport == '123':
                protocol_type = 'NTP'
            elif packet.udp.srcport == '53':
                protocol_type = 'DNS'
            elif packet.udp.srcport == '1900':
                protocol_type = 'SSDP'
            elif packet.udp.srcport == '427':
                protocol_type = 'SLP'
            elif packet.udp.srcport == '389':
                protocol_type = 'LDAP'
            elif packet.udp.srcport == '19':
                protocol_type = 'CHARGEN'
            elif packet.udp.srcport == '17':
                protocol_type = 'QOTD'
            else:
                # Check if the current data receiving rate is 25 Mbps or more
                current_bytes_received = psutil.net_io_counters().bytes_recv
                elapsed_time = time.time() - start_time
                data_received_per_sec = current_bytes_received - last_bytes_received
                current_rate = (data_received_per_sec * 8) / (1024 * 1024 * elapsed_time)  # Convert bytes to megabits and divide by elapsed time
                if current_rate >= 25:
                    protocol_type = 'GamePort'
        elif packet.transport_layer == 'TCP' and packet.tcp.flags_syn == '1':
            protocol_type = 'SYN'
        elif packet.transport_layer == 'UDP':
            if packet.udp.srcport == '161':
                protocol_type = 'SNMP'
        elif packet.eth.src == 'ff:ff:ff:ff:ff:ff' and packet.eth.dst == 'ff:ff:ff:ff:ff:ff':
            protocol_type = 'ARP'
        
        # Flag IP address based on protocol type
        if protocol_type and ip_src not in flagged_ips and ip_src not in ip_list:
            flagged_ips.add(ip_src)
            return ip_src, protocol_type
    except AttributeError:
        pass  # Ignore packets that don't have IP information
    return None, None

def main():
    ip_list = read_ip_addresses('ip_addresses.txt')
    last_modified_time = os.path.getmtime('ip_addresses.txt')
    flagged_ips = read_flagged_ips('flagged_ips.txt')  # Read flagged IPs from file
    total_data_received = {}  # Dictionary to track total data received per IP address
    flagged_count = 0
    start_time = time.time()
    last_bytes_received = psutil.net_io_counters().bytes_recv
    discord_notification_sent = False
    attack_detected = False
    last_drop_time = time.time()  # Initialize last drop time
    
    # Pool of worker processes
    pool = Pool()

    while True:
        for packet in sniff_udp_traffic():
            # Check if the IP list file has been modified
            current_modified_time = os.path.getmtime('ip_addresses.txt')
            if current_modified_time > last_modified_time:
                ip_list = read_ip_addresses('ip_addresses.txt')
                last_modified_time = current_modified_time

            # Process packets in parallel
            args = [(packet, ip_list, flagged_ips, total_data_received, start_time, last_bytes_received)]
            flagged_ip = pool.map(process_packet, args)

            # Write flagged IP addresses to file
            for ip, protocol_type in flagged_ip:
                if ip:
                    print(f"Flagged IP address: {ip} (Protocol: {protocol_type})")
                    write_flagged_ip('flagged_ips.txt', ip)
                    flagged_ips.add(ip)  # Update flagged IPs set
                    flagged_count += 1
            
            # Check if more than 10 IP addresses are flagged within 4 seconds
            if flagged_count >= 10 and time.time() - start_time <= 4 and not discord_notification_sent:
                # Calculate the current data receiving rate
                current_bytes_received = psutil.net_io_counters().bytes_recv
                elapsed_time = time.time() - start_time
                data_received_per_sec = current_bytes_received - last_bytes_received
                current_rate = (data_received_per_sec * 8) / (1024 * 1024 * elapsed_time)  # Convert bytes to megabits and divide by elapsed time
                
                if current_rate >= 25 and not attack_detected:  # Check if current rate is 25 Mbps or above and attack not detected
                    send_discord_notification(protocol_type, current_rate)
                    discord_notification_sent = True  # Set flag to indicate notification sent
                    attack_detected = True  # Set flag to indicate attack detected
                else:
                    discord_notification_sent = False  # Reset flag if rate is below 25 Mbps or attack detected
                
            # Check if receiving rate drops below 20 Mbps and an attack has been detected
            if attack_detected and time.time() - last_drop_time >= 35 and current_rate <= 20:
                attack_detected = False  # Reset flag to allow detecting another attack
                discord_notification_sent = False  # Reset flag to allow sending another notification

            # Reset flagged count if time window exceeds 4 seconds
            if time.time() - start_time > 4:
                flagged_count = 0  
                start_time = time.time()  
                last_bytes_received = psutil.net_io_counters().bytes_recv  

if __name__ == "__main__":
    main()
