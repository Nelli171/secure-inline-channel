# Secure Channel Study Modules

These simplified modules are for learning the helper code used in the inline-channel prototype. They are a study adaptation of files from the [secure-inline-channel repository](https://github.com/arelibaghdadian/secure-inline-channel). Credit that project when reusing its design or code.

## Files, in the requested order

1. `cache.py` — keeps ciphertext for an identical TCP retransmission.
2. `crypto.py` — X25519 key exchange, HKDF key derivation, AES-GCM, and nonce helper.
3. `tracker.py` — watches the TCP SYN and SYN-ACK to identify a connection.
4. `packets.py` — combines the cache and crypto helpers for a TCP payload.
5. `conn_id.py` — hashes endpoint and initial sequence information into a connection ID.

The filenames and some implementation details have been simplified. Device programs that import the old filenames may need their import paths updated to use the `sec` package.

## Important learning limitation

The nonce helper follows the reference prototype's sequence-number-and-length approach so that the receiver can reconstruct the nonce. This is not a universal guarantee of AES-GCM nonce uniqueness for every TCP connection, reuse, retransmission, or wraparound case. The cache only reuses ciphertext for an identical segment. Treat this as a classroom example, not production-ready cryptography.

The X25519 public keys are also unauthenticated in this example. A real secure handshake must authenticate the peer to prevent a man-in-the-middle attack.
