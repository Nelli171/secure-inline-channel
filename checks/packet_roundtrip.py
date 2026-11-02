"""Show payload encryption, retransmission reuse, and tag checking."""

from cryptography.exceptions import InvalidTag

from sec.cache import RetransmissionCache
from sec.conn_id import create_connection_id
from sec.crypto import derive_connection_key
from sec.packets import encrypt_tcp_payload, decrypt_tcp_payload


session_key = bytes(range(32))
connection_id = create_connection_id(
    "10.0.1.2", 50122, "10.0.3.2", 9000, 1000, 2000
)
direction = b"PC1-to-PC2"
traffic_key = derive_connection_key(session_key, connection_id, direction)
sequence = 123456
message = b"Hello from PC1."
cache = RetransmissionCache()

ciphertext = encrypt_tcp_payload(
    traffic_key, cache, connection_id, direction, sequence, message
)
same_ciphertext = encrypt_tcp_payload(
    traffic_key, cache, connection_id, direction, sequence, message
)
plain_text_again = decrypt_tcp_payload(traffic_key, sequence, ciphertext)

print("Encrypted length:", len(ciphertext))
print("Identical retransmission reused ciphertext:", ciphertext == same_ciphertext)
print("Recovered message matches:", plain_text_again == message)

changed_ciphertext = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
try:
    decrypt_tcp_payload(traffic_key, sequence, changed_ciphertext)
except InvalidTag:
    print("Changed ciphertext was rejected by the authentication tag.")
