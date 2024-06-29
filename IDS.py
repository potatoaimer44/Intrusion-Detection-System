import tkinter as tk
from tkinter import ttk
import threading
import pyshark
import netifaces

def read_rules():
    rule_file = "rules.txt"
    rules_list = []
    try:
        with open(rule_file, "r") as rf: 
            for line in rf:
                if line.startswith("alert"):
                    rules_list.append(line.strip())
    except FileNotFoundError:
        print("File not found:", rule_file)
    except Exception as e:
        print("An error occurred:", e)

    return rules_list

class PacketSniffer:
    def __init__(self):
        self.capture = None
        self.is_sniffing = False
        self.sniffing_thread = None
        self.alert_messages = []
        self.rules = read_rules()

    def start_sniffing(self, tree, alert_listbox):
        interface = 'Wi-Fi' #netifaces.gateways()['default'][netifaces.AF_INET][1]  # Change this to dynamic interface detection
        if interface:
            self.capture = pyshark.LiveCapture(interface=interface)
            self.is_sniffing = True
            self.sniffing_thread = threading.Thread(target=self.update_packets, args=(tree, alert_listbox))
            self.sniffing_thread.start()
        else:
            print("Couldn't detect default interface.")

    def stop_sniffing(self):
        self.is_sniffing = False
        if self.capture:
            self.capture.close()
        if self.sniffing_thread and self.sniffing_thread.is_alive():
            self.sniffing_thread.join()

    def update_packets(self, tree, alert_listbox):
        try:
            for packet in self.capture.sniff_continuously():
                if not self.is_sniffing:
                    break
                packet_details, alert_message = self.get_packet_details(packet)
                tree.insert("", "end", values=packet_details)
                tree.see(tree.get_children()[-1])

                if alert_message:
                    self.alert_messages.append(alert_message)
                    alert_listbox.insert(tk.END, alert_message)
                    alert_listbox.yview(tk.END)
        except Exception as e:
            print("An error occurred during packet capture:", e)

    def get_packet_details(self, packet):
        protocol = packet.transport_layer
        source_address = packet.ip.src if hasattr(packet, 'ip') else "Unknown"
        source_port = packet[packet.transport_layer].srcport if packet.transport_layer and hasattr(packet, packet.transport_layer) else "Unknown"
        destination_address = packet.ip.dst if hasattr(packet, 'ip') else "Unknown"
        destination_port = packet[packet.transport_layer].dstport if packet.transport_layer and hasattr(packet, packet.transport_layer) else "Unknown"
        packet_time = packet.sniff_time

        packet_details = (
            str(packet_time),
            protocol or 'Unknown',
            source_address,
            source_port,
            destination_address,
            destination_port
        )

        alert_message = self.check_for_alert(source_address, destination_address, protocol, source_port, destination_port)
        return packet_details, alert_message

    def check_for_alert(self, src_ip, dest_ip, protocol, src_port, dest_port):
        if protocol is None:
            protocol = "unknown"
        
        for rule in self.rules:
            rule_parts = rule.split()
            if len(rule_parts) == 7:
                rule_action, rule_protocol, rule_src_ip, rule_src_port, arrow, rule_dest_ip, rule_dest_port = rule_parts
                if (rule_protocol == protocol.lower() or rule_protocol == "any") and \
                        (rule_src_ip == src_ip or rule_src_ip == "any") and \
                        (rule_src_port == str(src_port) or rule_src_port == "any") and \
                        (rule_dest_ip == dest_ip or rule_dest_ip == "any") and \
                        (rule_dest_port == str(dest_port) or rule_dest_port == "any"):
                    return f"Alert: {rule_action} for packet from IP:{src_ip} | PORT:{src_port} --- to ---> IP: {dest_ip} | PORT:{dest_port}"
        
        return None


root = tk.Tk()
root.title("Packet Sniffer")

packet_sniffer = PacketSniffer()

columns = ("Timestamp", "Protocol", "Source Address", "Source Port", "Destination Address", "Destination Port")
tree = ttk.Treeview(root, columns=columns, show='headings')

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, minwidth=0, width=150)

tree.pack(expand=True, fill=tk.BOTH)

alert_listbox = tk.Listbox(root, width=150, height=10, bg='red', fg='white')
alert_listbox.pack(expand=True, fill=tk.BOTH)

start_button = tk.Button(root, text="Start Sniffing", command=lambda: packet_sniffer.start_sniffing(tree, alert_listbox))
start_button.pack(side=tk.LEFT)

stop_button = tk.Button(root, text="Stop Sniffing", command=packet_sniffer.stop_sniffing)
stop_button.pack(side=tk.RIGHT)

root.mainloop()
