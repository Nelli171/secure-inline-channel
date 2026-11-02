"""Encrypt and decrypt a short message with AES-GCM."""

from sec.crypto import encrypt_payload, decrypt_payload, generate_nonce


key = bytes(range(32))
message = b"A small message for the crypto example."
nonce = generate_nonce(123456, len(message))

ciphertext = encrypt_payload(key, nonce, message)
plain_text_again = decrypt_payload(key, nonce, ciphertext)

print("Encrypted bytes, shown as hex:", ciphertext.hex())
print("Recovered message:", plain_text_again)
print("Message is unchanged:", plain_text_again == message)
