import unittest
from unittest.mock import patch, MagicMock
from ids import PacketSniffer, read_rules, get_interfaces

class TestPacketSniffer(unittest.TestCase):
    @patch('ids.read_rules')
    def setUp(self, mock_read_rules):
        # Mock the read_rules function
        mock_read_rules.return_value = [
            "alert tcp any any -> any any (msg: 'Test rule 1';)",
            "!alert udp any any -> any any (msg: 'Test rule 2';)"
        ]
        self.sniffer = PacketSniffer()
    
    def test_read_rules(self):
        rules = read_rules()
        self.assertIn("alert tcp any any -> any any (msg: 'Test rule 1';)", rules)
    
    @patch('pyshark.LiveCapture')
    def test_start_sniffing(self, mock_live_capture):
        mock_capture_instance = mock_live_capture.return_value
        mock_capture_instance.sniff_continuously.return_value = []
        interface = 'wlan0'
        self.sniffer.start_sniffing(interface, MagicMock(), MagicMock())
        self.assertTrue(self.sniffer.is_sniffing)
        self.sniffer.stop_sniffing()
    
    def test_stop_sniffing(self):
        self.sniffer.is_sniffing = True
        self.sniffer.capture = MagicMock()
        self.sniffer.sniffing_thread = MagicMock()
        self.sniffer.sniffing_thread.is_alive.return_value = True
        self.sniffer.stop_sniffing()
        self.assertFalse(self.sniffer.is_sniffing)
    
    @patch('ids.netifaces.interfaces')
    @patch('ids.netifaces.ifaddresses')
    def test_get_interfaces(self, mock_ifaddresses, mock_interfaces):
        mock_interfaces.return_value = ['eth0', 'lo', 'wifi0']
        mock_ifaddresses.side_effect = lambda iface: {netifaces.AF_INET: [{}]} if iface != 'lo' else {}
        interfaces = get_interfaces()
        self.assertIn('eth0', interfaces)
        self.assertIn('wifi0', interfaces)
        self.assertNotIn('lo', interfaces)
    
    @patch('ids.PacketSniffer.get_packet_details')
    @patch('ids.PacketSniffer.send_alert')
    def test_update_packets(self, mock_send_alert, mock_get_packet_details):
        mock_get_packet_details.return_value = (
            ("2024-01-01 00:00:00", "TCP", "192.168.1.1", "80", "192.168.1.2", "443"),
            "Test alert message - 192.168.1.1:80 - TCP - 192.168.1.2:443"
        )
        mock_packet = MagicMock()
        mock_packet.sniff_continuously.return_value = [mock_packet]
        self.sniffer.capture = mock_packet
        self.sniffer.is_sniffing = True
        tree_mock = MagicMock()
        alert_tree_mock = MagicMock()
        self.sniffer.update_packets(tree_mock, alert_tree_mock)
        tree_mock.insert.assert_called()
        alert_tree_mock.insert.assert_called()
        mock_send_alert.assert_called()
    
    def test_get_packet_details(self):
        packet_mock = MagicMock()
        packet_mock.highest_layer = "TCP"
        packet_mock.ip.src = "192.168.1.1"
        packet_mock.ip.dst = "192.168.1.2"
        packet_mock.tcp.srcport = "12345"
        packet_mock.tcp.dstport = "80"
        packet_mock.sniff_time = datetime.now()
        
        details, alert = self.sniffer.get_packet_details(packet_mock)
        self.assertIsNotNone(details)
        self.assertIn("TCP", details)
    
    def test_check_for_alert(self):
        self.sniffer.rules = [
            "alert tcp any any -> any any (msg: 'Test rule 1';)"
        ]
        alert_message = self.sniffer.check_for_alert("192.168.1.1", "192.168.1.2", "TCP", "80", "443")
        self.assertEqual(alert_message, "Test rule 1 - 192.168.1.1:80 - TCP - 192.168.1.2:443")
    
    @patch('smtplib.SMTP')
    def test_send_alert(self, mock_smtp):
        mock_smtp_instance = mock_smtp.return_value
        alert_message = "Test alert message"
        self.sniffer.send_alert(alert_message)
        mock_smtp_instance.sendmail.assert_called()

if __name__ == '__main__':
    unittest.main()
