"""Intercept selected TCP packets and protect their payloads on Device1."""

from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw

from sec.cache import RetransmissionCache
from sec.crypto import derive_connection_key
from sec.packets import encrypt_tcp_payload, decrypt_tcp_payload
from sec.tracker import TCPConnectionTracker


PC1_IP = "10.0.1.2"
PC2_IP = "10.0.3.2"
QUEUE_NUMBER = 1
KEY_FILE = "/tmp/device1-session.key"


with open(KEY_FILE, "rb") as key_file:
    session_key = key_file.read()

tracker = TCPConnectionTracker()
cache = RetransmissionCache()


def process_packet(queued_packet):
    ip_packet = IP(queued_packet.get_payload())

    if TCP not in ip_packet:
        queued_packet.accept()
        return

    tcp_packet = ip_packet[TCP]
    tracker.process_packet(ip_packet)

    # Decide whether this is PC1-to-PC2 or PC2-to-PC1 traffic.
    if ip_packet.src == PC1_IP and ip_packet.dst == PC2_IP:
        direction = b"PC1-to-PC2"
        decrypting = False
        flow = ((ip_packet.src, tcp_packet.sport),
                (ip_packet.dst, tcp_packet.dport))
    elif ip_packet.src == PC2_IP and ip_packet.dst == PC1_IP:
        direction = b"PC2-to-PC1"
        decrypting = True
        flow = ((ip_packet.dst, tcp_packet.dport),
                (ip_packet.src, tcp_packet.sport))
    else:
        queued_packet.accept()
        return

    original_payload = bytes(tcp_packet.payload)
    if not original_payload:
        queued_packet.accept()
        return

    connection = tracker.connections.get(flow)
    if connection is None or connection["server_isn"] is None:
        print("TCP connection is not ready; dropping payload packet.")
        queued_packet.drop()
        return

    connection_id = connection["connection_id"]
    traffic_key = derive_connection_key(
        session_key, connection_id, direction
    )

    try:
        if decrypting:
            changed_payload = decrypt_tcp_payload(
                traffic_key, tcp_packet.seq, original_payload
            )
            print("Device1 decrypted a payload.")
        else:
            changed_payload = encrypt_tcp_payload(
                traffic_key,
                cache,
                connection_id,
                direction,
                tcp_packet.seq,
                original_payload,
            )
            print("Device1 encrypted a payload.")
    except Exception as error:
        print("Packet could not be processed:", error)
        queued_packet.drop()
        return

    tcp_packet.remove_payload()
    if changed_payload:
        tcp_packet.add_payload(Raw(load=changed_payload))

    # Scapy rebuilds these fields when the packet is serialized.
    del ip_packet.len
    del ip_packet.chksum
    del tcp_packet.chksum
    queued_packet.set_payload(bytes(ip_packet))
    queued_packet.accept()


def main():
    queue = NetfilterQueue()
    queue.bind(QUEUE_NUMBER, process_packet)
    print("Device1 packet handler is waiting for queued packets.")

    try:
        queue.run()
    except KeyboardInterrupt:
        print("Stopping Device1 packet handler.")
    finally:
        queue.unbind()


if __name__ == "__main__":
    main()
