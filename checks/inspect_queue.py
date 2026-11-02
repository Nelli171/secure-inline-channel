"""Print basic details about TCP packets received through NFQUEUE."""

from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP


QUEUE_NUMBER = 1


def inspect_packet(queued_packet):
    ip_packet = IP(queued_packet.get_payload())

    if TCP in ip_packet:
        tcp_packet = ip_packet[TCP]
        payload = bytes(tcp_packet.payload)
        print(
            "TCP packet:", ip_packet.src, "->", ip_packet.dst,
            "payload bytes:", len(payload)
        )

    # This educational inspector does not modify the packet.
    queued_packet.accept()


def main():
    queue = NetfilterQueue()
    queue.bind(QUEUE_NUMBER, inspect_packet)
    print("Listening for packets on the configured lab queue.")

    try:
        queue.run()
    except KeyboardInterrupt:
        print("Stopping packet inspection.")
    finally:
        queue.unbind()


if __name__ == "__main__":
    main()
