import tkinter as tk
from tkinter import ttk
import threading
from scapy.all import sniff, IP, TCP, UDP
import ipaddress
import netifaces
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
import logging

def read_rules():
    rule_file = "rules.txt"
    rules_list = []
    try:
        with open(rule_file, "r") as rf:
            for line in rf:
                if line.startswith("alert") or line.startswith("!alert"):
                    rules_list.append(line.strip())
    except FileNotFoundError:
        print("File not found:", rule_file)
    return rules_list

class PacketSniffer:
    def __init__(self):
        self.is_sniffing = False
        self.sniffing_thread = None
        self.alert_messages = []
        self.rules = read_rules()
        logging.basicConfig(filename='ids.log', level=logging.INFO, format='%(asctime)s %(message)s')

    def start_sniffing(self, interface, tree, alert_tree):
        if interface:
            self.is_sniffing = True
            self.sniffing_thread = threading.Thread(target=self.update_packets, args=(interface, tree, alert_tree))
            self.sniffing_thread.start()
        else:
            print("No interface selected. Please specify manually.")

    def stop_sniffing(self):
        self.is_sniffing = False
        if self.sniffing_thread and self.sniffing_thread.is_alive():
            self.sniffing_thread.join()

    def update_packets(self, interface, tree, alert_tree):
        try:
            sniff(iface=interface, prn=lambda packet: self.process_packet(packet, tree, alert_tree), stop_filter=lambda _: not self.is_sniffing)
        except Exception as e:
            print("An error occurred during packet sniffing:", e)

    def process_packet(self, packet, tree, alert_tree):
        packet_details, alert_message = self.get_packet_details(packet)
        if packet_details:
            tree.insert("", "end", values=packet_details)
            tree.see(tree.get_children()[-1])

        if alert_message:
            self.alert_messages.append(alert_message)
            alert_details = alert_message.split(' - ')
            alert_tree.insert("", "end", values=alert_details, tags=('alert',))
            alert_tree.see(alert_tree.get_children()[-1])
            logging.info(alert_message)
            self.send_alert(alert_message)

    def get_packet_details(self, packet):
        try:
            protocol = packet.getlayer(2).name if packet.haslayer(IP) else "Unknown"

            source_address = packet[IP].src if packet.haslayer(IP) else "Unknown"
            destination_address = packet[IP].dst if packet.haslayer(IP) else "Unknown"

            if packet.haslayer(TCP):
                source_port = packet[TCP].sport
                destination_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                source_port = packet[UDP].sport
                destination_port = packet[UDP].dport
            else:
                source_port = "Unknown"
                destination_port = "Unknown"

            packet_time = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')

            packet_details = (
                str(packet_time),
                protocol,
                source_address,
                source_port,
                destination_address,
                destination_port
            )

            alert_message = self.check_for_alert(source_address, destination_address, protocol, source_port, destination_port)
            return packet_details, alert_message
        except AttributeError as e:
            print("AttributeError:", e)
            return ("Unknown", "Unknown", "Unknown", "Unknown", "Unknown", "Unknown"), None

    def check_for_alert(self, src_ip, dest_ip, protocol, src_port, dest_port):
        if protocol is None:
            protocol = "unknown"

        for rule in self.rules:
            rule_parts = rule.split()
            if len(rule_parts) >= 7:
                rule_action, rule_protocol, rule_src_ip, rule_src_port, arrow, rule_dest_ip, rule_dest_port, *message = rule_parts
                message = " ".join(message)
                if (rule_protocol.lower() == protocol.lower() or rule_protocol == "any") and \
                   (self.ip_matches(rule_src_ip, src_ip)) and \
                   (rule_src_port == str(src_port) or rule_src_port == "any") and \
                   (self.ip_matches(rule_dest_ip, dest_ip)) and \
                   (rule_dest_port == str(dest_port) or rule_dest_port == "any"):
                    return f"{message} - {src_ip}:{src_port} - {protocol} - {dest_ip}:{dest_port}"

        return None

    def ip_matches(self, rule_ip, packet_ip):
        if rule_ip == "any":
            return True
        if packet_ip == "Unknown":
            return False
        if '/' in rule_ip:  # handle IP range
            return ipaddress.ip_address(packet_ip) in ipaddress.ip_network(rule_ip)
        return rule_ip == packet_ip

    def send_alert(self, alert_message):
        try:
            # Configure email parameters
            smtp_server = 'smtp.gmail.com'
            smtp_port = 587
            sender_email = 'www.potatoaimer444@gmail.com'
            receiver_email = 'www.aayushaayun@gmail.com'
            password = 'bfwb zabs haxk dldc'

            msg = MIMEText(alert_message)
            msg['Subject'] = 'IDS Alert'
            msg['From'] = sender_email
            msg['To'] = receiver_email

            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(sender_email, password)
                server.sendmail(sender_email, receiver_email, msg.as_string())
        except Exception as e:
            print("Failed to send alert email:", e)

def get_interfaces():
    interfaces = netifaces.interfaces()
    filtered_interfaces = []
    for interface in interfaces:
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            if 'wifi' in interface.lower() or 'eth' in interface.lower() or 'en' in interface.lower():
                filtered_interfaces.append(interface)
    return filtered_interfaces

# Create the main Tkinter window
root = tk.Tk()
root.title("Intrusion Detection System")
root.geometry("1000x600")

packet_sniffer = PacketSniffer()

# Create frames for better layout
frame_top = tk.Frame(root)
frame_top.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=5)

frame_bottom = tk.Frame(root)
frame_bottom.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True, padx=10, pady=5)

# Create a Treeview widget for displaying packet information in table format
columns = ("Timestamp", "Protocol", "Source Address", "Source Port", "Destination Address", "Destination Port")
tree = ttk.Treeview(frame_top, columns=columns, show='headings')

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, minwidth=0, width=150)

tree.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

# Add a scrollbar to the treeview
tree_scrollbar = ttk.Scrollbar(frame_top, orient=tk.VERTICAL, command=tree.yview)
tree.configure(yscroll=tree_scrollbar.set)
tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Create a Treeview widget for displaying alert messages in table format
alert_columns = ("Message", "Source", "Protocol", "Destination")
alert_tree = ttk.Treeview(frame_bottom, columns=alert_columns, show='headings')

for col in alert_columns:
    alert_tree.heading(col, text=col)
    alert_tree.column(col, minwidth=0, width=150)

alert_tree.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

# Add a scrollbar to the alert treeview
alert_tree_scrollbar = ttk.Scrollbar(frame_bottom, orient=tk.VERTICAL, command=alert_tree.yview)
alert_tree.configure(yscroll=alert_tree_scrollbar.set)
alert_tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Configure tags for the alert_tree
alert_tree.tag_configure('alert', background='red', foreground='white')

# Dropdown for network interfaces
interface_label = tk.Label(root, text="Select Interface:")
interface_label.pack(side=tk.LEFT, padx=5)

interfaces = get_interfaces()
interface_var = tk.StringVar(value=interfaces[0] if interfaces else '')
interface_menu = ttk.Combobox(root, textvariable=interface_var, values=interfaces)
interface_menu.pack(side=tk.LEFT, padx=5)

# Create a Start button to start sniffing
start_button = tk.Button(root, text="Start Sniffing", command=lambda: packet_sniffer.start_sniffing(interface_var.get(), tree, alert_tree))
start_button.pack(side=tk.LEFT, padx=10, pady=10)

# Create a Stop button to stop sniffing
stop_button = tk.Button(root, text="Stop Sniffing", command=packet_sniffer.stop_sniffing)
stop_button.pack(side=tk.RIGHT, padx=10, pady=10)

# Start the Tkinter event loop
root.mainloop()
