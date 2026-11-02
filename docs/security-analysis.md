# Security Review of the Inline Channel Prototype

> **Source:** This review paraphrases the security analysis documented in the [secure-inline-channel repository](https://github.com/arelibaghdadian/secure-inline-channel). The implementation and design concepts belong to that project.
>
> **Prepared by:** Nena Hagopian.

## 1. What is being protected

The prototype places Device1 and Device2 between PC1 and PC2. It aims to protect selected TCP payloads while they travel between the inline devices. The outer IPv4 and TCP packets are processed and forwarded by the Linux devices; the destination-side device checks and decrypts the protected payload before delivering the restored packet to the endpoint.

The design combines a key agreement, key derivation, directional keys, and authenticated encryption. This document summarizes the intended protections and the limitations stated for the prototype. It is not a production security certification.

## 2. Key agreement with X25519

Each device creates an X25519 private/public key pair and sends its public key to the peer. Each side uses its own private key with the received public key to calculate the same shared secret. The private keys remain on their respective devices.

X25519 lets the devices calculate a common secret without sending that secret across the network. However, this property alone does not prove who sent a public key.

### Key-exchange limitation

The current handshake does not authenticate the public keys. An attacker who can intercept and replace handshake messages could establish separate keys with each device and relay traffic between them. This is a man-in-the-middle risk. A stronger design would authenticate the peer keys, for example with certificates or a pre-shared authentication key.

## 3. Deriving keys with HKDF-SHA256

The shared X25519 secret is input to HKDF-SHA256 to produce a 32-byte session key. The prototype then derives connection-specific keys using the connection identifier and a direction label as context.

Separate keys are used for PC1-to-PC2 and PC2-to-PC1 traffic. This key separation helps prevent the two traffic directions from sharing one AES key directly. The connection identifier is formed by hashing endpoint addresses, ports, and the initial TCP sequence numbers with SHA-256.

## 4. AES-256-GCM protection

The prototype uses AES-256-GCM on TCP payload bytes. GCM provides confidentiality by encrypting the payload and provides integrity protection through an authentication tag. The receiver must successfully verify the tag before it accepts the decrypted plaintext.

The documented implementation uses a 32-byte key, a 12-byte nonce, and a 16-byte tag. Since the tag is included with the ciphertext, a protected payload is 16 bytes longer than the original. For example, a 35-byte payload becomes 51 bytes of ciphertext plus tag.

If authentication fails, the receiver rejects the data and drops the packet rather than forwarding unverified plaintext.

## 5. Nonce construction and retransmissions

AES-GCM security depends on nonce management: a nonce must not be reused with the same key. In this prototype, the 12-byte nonce is constructed from the TCP sequence number, the original payload length, and six fixed zero bytes.

A retransmission cache uses the connection identifier, direction, sequence number, and payload length to find previously encrypted segments. For a matching segment with identical plaintext, the cached ciphertext is reused. If a cache entry is found with different plaintext, encryption is refused. The cache has a maximum size and rejects new encryption when full.

### Nonce and cache limitations

The project documents this scheme as a bounded prototype approach, not a universal uniqueness guarantee. TCP sequence numbers can wrap or appear again when connections are reused; tracking every lifecycle and retransmission case is more complex than the current cache handles. A production design would need a rigorously specified per-key nonce allocation and connection-state strategy.

## 6. Connection-specific key context

The devices observe TCP's initial SYN and SYN-ACK packets to learn the client and server endpoints and their initial sequence numbers. These values are hashed into a connection identifier. HKDF uses that identifier together with a direction label when deriving each connection's traffic key.

This gives different TCP connections and different directions separate derived keys. The documented tracker does not cover every TCP lifecycle event, connection reuse case, or concurrent-flow situation, so the resulting key context should be understood within the prototype's tested scope.

## 7. Packet integrity during processing

The inline processors extract only the TCP payload for AES-GCM processing, replace it with the protected bytes or recovered plaintext, and recalculate the relevant IP and TCP lengths and checksums. The receiving device verifies the GCM tag before restoring plaintext. The implementation otherwise retains the packet header fields it processes.

The authentication tag detects changes to protected data. The project description does not claim that every IP or TCP header field is authenticated as AES-GCM associated data; therefore, payload authentication should not be described as complete authentication of the entire packet.

## 8. Operational and packet-size limits

Appending the 16-byte tag increases packet size. The prototype documentation lists MTU and fragmentation behavior as areas needing further development. It also notes that connection tracking and retransmission handling are incomplete for a general-purpose TCP gateway.

The documented demonstration was performed in a controlled Linux network namespace environment. That does not establish that the implementation is ready for arbitrary networks or production traffic.

## 9. Security summary

| Area | Prototype behavior | Limitation to explain |
|---|---|---|
| Key agreement | X25519 derives a shared secret without transmitting the secret itself. | Public keys are unauthenticated, so a man-in-the-middle attack is possible. |
| Key derivation | HKDF-SHA256 derives a session key and direction- and connection-specific keys. | The security depends on the handshake secret and correct connection state. |
| Payload protection | AES-256-GCM encrypts TCP payloads and adds a 16-byte authentication tag. | The tag authenticates the protected data, not automatically every packet header field. |
| Nonces | A nonce is derived from TCP sequence information and payload length; identical retransmissions reuse cached ciphertext. | The current approach does not guarantee uniqueness for every possible TCP lifecycle. |
| Packet delivery | The receiver verifies the tag before forwarding decrypted payload bytes and updates lengths and checksums. | MTU, fragmentation, and full connection handling need more work. |
| Test scope | The repository reports a controlled Linux namespace demonstration. | This is not evidence of production readiness. |

## 10. Conclusion

The prototype demonstrates how X25519, HKDF-SHA256, directional key derivation, and AES-256-GCM can be combined in an inline TCP payload processor. Its documented tests demonstrate the basic bidirectional flow in a controlled environment. The unauthenticated handshake, limited nonce and retransmission design, incomplete TCP lifecycle handling, and packet-size concerns remain important limitations to state when presenting the project.
