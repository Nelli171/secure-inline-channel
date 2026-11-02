"""Connect to Device2 and derive Device1's session key."""

import socket

from sec.crypto import generate_key_pair, derive_session_key


DEVICE2_IP = "10.0.2.2"
DEVICE2_PORT = 5000
KEY_FILE = "/tmp/device1-session.key"
PUBLIC_KEY_SIZE = 32


def receive_exact(sock, size):
    """Read exactly size bytes from a TCP socket."""
    parts = []
    remaining = size

    while remaining > 0:
        part = sock.recv(remaining)
        if not part:
            raise ConnectionError("Device2 closed the connection early")
        parts.append(part)
        remaining -= len(part)

    return b"".join(parts)


def establish_session():
    private_key, public_key = generate_key_pair()

    with socket.create_connection((DEVICE2_IP, DEVICE2_PORT)) as sock:
        sock.sendall(public_key)
        peer_public_key = receive_exact(sock, PUBLIC_KEY_SIZE)

    session_key = derive_session_key(private_key, peer_public_key)
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(session_key)

    print("Device1 session key was created and saved.")


if __name__ == "__main__":
    establish_session()
