"""Feed a made-up SYN and SYN-ACK to the TCP connection tracker."""

from scapy.all import IP, TCP

from sec.conn_id import create_connection_id
from sec.tracker import TCPConnectionTracker


tracker = TCPConnectionTracker()

client_syn = (
    IP(src="10.0.1.2", dst="10.0.3.2")
    / TCP(sport=50122, dport=9000, flags="S", seq=1000)
)
server_syn_ack = (
    IP(src="10.0.3.2", dst="10.0.1.2")
    / TCP(sport=9000, dport=50122, flags="SA", seq=2000, ack=1001)
)

tracker.process_packet(client_syn)
connection_id = tracker.process_packet(server_syn_ack)

expected_id = create_connection_id(
    "10.0.1.2", 50122, "10.0.3.2", 9000, 1000, 2000
)

print("Tracker made a connection ID:", connection_id is not None)
print("ID matches the expected value:", connection_id == expected_id)
