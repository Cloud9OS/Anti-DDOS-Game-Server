# DDoS Attack Detection and IP Blocking System

This system is designed to detect and mitigate Distributed Denial of Service (DDoS) attacks by monitoring network traffic and blocking flagged IP addresses. It consists of two main components:

1. **Sniffer Script (`sniffer.py`):**
    - The `sniffer.py` script monitors network traffic, identifies potential DDoS attack patterns, and flags IP addresses associated with suspicious activity.
    - It is highly customizable and can be configured to monitor specific ports used by game servers or other services susceptible to DDoS attacks.
    - Detected attacks are reported via Discord webhooks for real-time notifications.

2. **Blocking Bot (`bot.py`):**
    - The `bot.py` script serves as a Discord bot that receives flagged IP addresses from `sniffer.py` and automatically blocks them using firewall rules.
    - It continuously checks for new flagged IP addresses and adds them to the firewall block list, providing protection against ongoing attacks.

## How It Works

### Sniffer Script (`sniffer.py`)

The `sniffer.py` script employs packet sniffing techniques to analyze network traffic. It monitors UDP traffic on specified ports, identifies potential DDoS attack patterns based on traffic characteristics, and flags IP addresses associated with suspicious activity.

#### Detection Criteria:
- **Protocol Analysis:** Differentiates between various UDP and TCP protocols to identify potentially malicious traffic.
- **Traffic Rate Monitoring:** Monitors the rate of incoming traffic and flags IP addresses exceeding a predefined threshold (e.g., 25 Mbps) for suspicious activity.
- **Attack Type Identification:** Recognizes common DDoS attack patterns, such as NTP amplification, DNS amplification, and UDP flooding.

### Blocking Bot (`bot.py`)

The `bot.py` script acts as a Discord bot responsible for implementing IP blocking measures based on flagged IP addresses received from `sniffer.py`.

#### Key Features:
- **Real-time IP Blocking:** Automatically adds flagged IP addresses to the firewall block list to prevent further access.
- **Customizable Commands:** Supports commands for manual IP blocking/unblocking and provides information about the bot's functionality.
- **Logging and Reporting:** Logs blocked IP addresses for future analysis and sends notifications about blocked IPs and potential flood alerts to designated Discord channels.

## Configuration

### Sniffer Script (`sniffer.py`)
1. Replace `Your_Discord_webhook` with your actual Discord webhook URL to receive attack notifications.
2. Configure the script to monitor the desired ports used by your game server or services susceptible to DDoS attacks `bpf_filter=`.
3. Ensure that the network interface specified in `sniff_udp_traffic()` function has the necessary permissions to capture network traffic.
4. Whitelist IP Addresses:
    - Ensure to maintain a list of whitelisted IP addresses in the `ip_addresses.txt` file.
    - Whitelisted IP addresses will not be flagged or blocked by the system.
    - You can use tools like [Squad Protector](https://github.com/Cloud9OS/Squad-Protector) to log whitelisted IP addresses of players in games like Squad.
    - For other game servers or services, maintain your own list of whitelisted IP addresses in the `ip_addresses.txt` file.

### Blocking Bot (`bot.py`)
1. Set your Discord token, server ID (`GUILD_ID`), and channel ID (`CHANNEL_ID`) in the script.
2. Replace the list of `allowed_users` with the Discord user IDs authorized to send commands to the bot.
3. Customize command prefixes and functionalities according to your preference.

## Usage

1. Start the `sniffer.py` script to monitor network traffic and detect potential DDoS attacks.
2. Run the `bot.py` script to deploy the Discord bot for automatic IP blocking.
3. Configure Discord webhooks for receiving attack notifications and blocked IP alerts.
4. Monitor Discord channels for notifications and take necessary actions based on reported attacks and blocked IP addresses.

**Note:** Ensure that the firewall is enabled on the system running `bot.py` to effectively block IP addresses.

## Additional Notes

- This system is designed primarily for Windows environments. For Linux-based systems, consider adapting firewall commands and dependencies accordingly.
- Regularly update the system with new attack patterns and adjust detection thresholds as necessary to improve accuracy and responsiveness.
