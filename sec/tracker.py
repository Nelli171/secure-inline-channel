"""Build an identifier after observing a TCP SYN and SYN-ACK."""

from scapy.all import IP, TCP

from sec.conn_id import create_connection_id


class TCPConnectionTracker:
    SYN = 0x02
    ACK = 0x10

    def __init__(self):
        self.connections = {}

    def process_packet(self, packet):
        if IP not in packet or TCP not in packet:
            return None

        ip = packet[IP]
        tcp = packet[TCP]
        source = (ip.src, tcp.sport)
        destination = (ip.dst, tcp.dport)
        flags = int(tcp.flags)

        # Save the client details from the opening SYN.
        if flags & self.SYN and not flags & self.ACK:
            self.connections[(source, destination)] = {
                "client_ip": ip.src,
                "client_port": tcp.sport,
                "server_ip": ip.dst,
                "server_port": tcp.dport,
                "client_isn": tcp.seq,
                "server_isn": None,
            }
            return None

        # A SYN-ACK travels back from the server to the client.
        if flags & (self.SYN | self.ACK) == (self.SYN | self.ACK):
            key = (destination, source)
            connection = self.connections.get(key)
            if connection is None:
                return None

            connection["server_isn"] = tcp.seq
            connection_id = create_connection_id(
                connection["client_ip"],
                connection["client_port"],
                connection["server_ip"],
                connection["server_port"],
                connection["client_isn"],
                connection["server_isn"],
            )
            connection["connection_id"] = connection_id
            return connection_id

        return None
