"""Demonstrate the prototype's sequence-and-length nonce helper."""

from sec.crypto import generate_nonce


same_segment_a = generate_nonce(123456, 35)
same_segment_b = generate_nonce(123456, 35)
new_sequence = generate_nonce(123457, 35)
new_length = generate_nonce(123456, 40)

print("Same inputs produce the same nonce:", same_segment_a == same_segment_b)
print("Changing sequence changes this example nonce:", same_segment_a != new_sequence)
print("Changing length changes this example nonce:", same_segment_a != new_length)
print("This simple demonstration does not prove uniqueness for all TCP cases.")
