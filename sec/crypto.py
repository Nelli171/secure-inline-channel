"""Basic key-exchange, key-derivation, and AES-GCM helpers."""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def generate_key_pair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, public_key


def derive_session_key(private_key, peer_public_bytes):
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared_secret = private_key.exchange(peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"secure-inline-channel-v1",
    ).derive(shared_secret)


def derive_connection_key(session_key, connection_id, direction):
    context = b"secure-inline-channel-v1|" + connection_id + b"|" + direction
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context,
    ).derive(session_key)


def generate_nonce(sequence_number, payload_length):
    if not 0 <= sequence_number <= 0xFFFFFFFF:
        raise ValueError("TCP sequence number is out of range")
    if not 0 <= payload_length <= 0xFFFF:
        raise ValueError("Payload length is out of range")

    return (
        sequence_number.to_bytes(4, "big")
        + payload_length.to_bytes(2, "big")
        + bytes(6)
    )


def encrypt_payload(key, nonce, plaintext):
    return AESGCM(key).encrypt(nonce, plaintext, None)


def decrypt_payload(key, nonce, ciphertext):
    return AESGCM(key).decrypt(nonce, ciphertext, None)
