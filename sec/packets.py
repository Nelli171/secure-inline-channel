"""Encrypt and decrypt TCP payload bytes using the helper modules."""

from sec.crypto import (
    decrypt_payload,
    encrypt_payload,
    generate_nonce,
)


def encrypt_tcp_payload(
    connection_key,
    cache,
    connection_id,
    direction,
    sequence_number,
    plaintext,
):
    old_ciphertext = cache.get(
        connection_id, direction, sequence_number, plaintext
    )
    if old_ciphertext is not None:
        return old_ciphertext

    nonce = generate_nonce(sequence_number, len(plaintext))
    ciphertext = encrypt_payload(connection_key, nonce, plaintext)
    cache.store(
        connection_id, direction, sequence_number, plaintext, ciphertext
    )
    return ciphertext


def decrypt_tcp_payload(connection_key, sequence_number, ciphertext):
    tag_size = 16
    plaintext_length = len(ciphertext) - tag_size
    if plaintext_length < 0:
        raise ValueError("Protected payload is too short")

    nonce = generate_nonce(sequence_number, plaintext_length)
    return decrypt_payload(connection_key, nonce, ciphertext)
