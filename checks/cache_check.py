"""Show how the retransmission cache handles a repeated segment."""

from sec.cache import RetransmissionCache


cache = RetransmissionCache()
flow_id = b"demo-flow"
direction = b"PC1-to-PC2"
sequence = 123456
message = b"Hello from PC1!"
ciphertext = b"sample ciphertext"

cache.store(flow_id, direction, sequence, message, ciphertext)
print("Saved ciphertext:", cache.get(flow_id, direction, sequence, message))

try:
    cache.get(flow_id, direction, sequence, b"Different text!")
except ValueError:
    print("The cache rejected different data for the same segment.")

other_flow = cache.get(b"another-flow", direction, sequence, message)
print("A different flow has its own entry:", other_flow is None)
