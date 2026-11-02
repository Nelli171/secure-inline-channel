# Secure Channel Design Overview

> **Source:** These study notes paraphrase the architecture documented in the [secure-inline-channel repository](https://github.com/arelibaghdadian/secure-inline-channel). The implementation and design concepts belong to that project.
>
> **Prepared by:** Nena Hagopian.

## 1. Purpose and traffic path

The prototype places two Linux packet-processing devices between two endpoint computers. The devices protect selected IPv4/TCP payloads while the traffic crosses the link between them. After the receiving device authenticates and decrypts a payload, it forwards the restored packet to the destination host.

```text
PC1  →  Device1  →  Device2  →  PC2
PC1  ←  Device1  ←  Device2  ←  PC2
```

The reverse path uses the same arrangement, with Device2 encrypting and Device1 decrypting.

## 2. Virtual network layout

Four Linux network namespaces represent the two hosts and two inline devices. A pair of virtual Ethernet interfaces joins each neighboring pair.

| Namespace | Interface | IPv4 address |
|---|---|---|
| PC1 | `pc1-eth0` | `10.0.1.2/24` |
| Device1 | `d1-eth0` | `10.0.1.1/24` |
| Device1 | `d1-eth1` | `10.0.2.1/24` |
| Device2 | `d2-eth0` | `10.0.2.2/24` |
| Device2 | `d2-eth1` | `10.0.3.1/24` |
| PC2 | `pc2-eth0` | `10.0.3.2/24` |

The virtual links are `pc1-eth0 ↔ d1-eth0`, `d1-eth1 ↔ d2-eth0`, and `d2-eth1 ↔ pc2-eth0`. IP forwarding is enabled on both devices so packets can travel between their interfaces.

## 3. Establishing shared keys

Before payload protection starts, Device1 and Device2 exchange X25519 public keys over a TCP control connection. Each device combines its private key with the peer's public key to calculate the same shared secret. HKDF-SHA256 then derives a 32-byte session key from that secret.

The reference implementation writes the derived key to a local temporary file on each device. Later, each packet processor reads its device's key from that file.

## 4. Identifying TCP connections

Each inline device watches the TCP handshake. It records the first client SYN and the server's SYN-ACK, including the endpoint addresses, port numbers, and initial sequence numbers. The project hashes this information with SHA-256 to produce a connection identifier.

That identifier, together with the traffic direction, is used as context when deriving a separate AES key for each TCP connection and direction. This keeps PC1-to-PC2 traffic and PC2-to-PC1 traffic on different keys.

## 5. Protecting packets in each direction

### PC1 to PC2

1. Device1 receives a selected forwarded TCP packet through NFQUEUE.
2. It identifies the connection and selects the PC1-to-PC2 key.
3. It encrypts the TCP payload with AES-GCM. The ciphertext returned by AES-GCM includes the authentication tag.
4. Device1 replaces the payload and forwards the modified packet toward Device2.
5. Device2 intercepts the packet, derives the matching connection key, verifies the tag, and decrypts the payload.
6. Device2 replaces the protected bytes with plaintext and forwards the restored packet to PC2.

### PC2 to PC1

The reverse flow is the same in the opposite order: Device2 encrypts with the PC2-to-PC1 key, and Device1 verifies and decrypts the packet before forwarding it to PC1.

## 6. Packet interception and rebuilding

The prototype uses Linux NFQUEUE rules to send selected forwarded packets to Python programs in userspace. The programs inspect IPv4 and TCP fields, extract the TCP payload, and perform the appropriate encryption or decryption operation.

After replacing the payload, the packet processor recalculates the relevant IP and TCP lengths and checksums. Other header fields are retained by the implementation. Protected packets are then accepted back into the kernel's forwarding path; packets that fail processing or authentication are dropped.

## 7. Retransmitted TCP segments

TCP can retransmit a segment. The reference implementation forms a cache key from the connection identifier, direction, sequence number, and payload length. If the same segment is seen again with identical plaintext, the cached ciphertext is reused. If the same cache entry is associated with different plaintext, encryption is rejected. The cache also has a capacity limit and refuses additional entries when full.

This is a bounded prototype strategy. Its own security notes say that the nonce construction and retransmission handling do not cover every possible TCP lifecycle case.

## 8. Main components

| Component | Responsibility |
|---|---|
| Linux namespaces and virtual Ethernet pairs | Simulate the two hosts and two inline devices in an isolated topology. |
| NFQUEUE and firewall rules | Divert selected forwarded packets to the device programs. |
| Scapy | Parse and rebuild IPv4/TCP packets. |
| X25519 | Let the two devices calculate a shared secret. |
| HKDF-SHA256 | Derive the session key and connection-specific directional keys. |
| AES-256-GCM | Encrypt the payload and provide an authentication tag. |
| Connection tracker and retransmission cache | Associate packets with connections and reuse ciphertext for identical retransmissions. |

## 9. Scope and known limitations

This design demonstrates bidirectional payload protection in a controlled Linux environment. It is an educational prototype, not a production-ready TCP security gateway.

The reference documentation identifies these limitations:

- The X25519 public keys are not authenticated, so the handshake is vulnerable to a man-in-the-middle attack.
- The nonce is derived from TCP sequence information and payload length; the project does not guarantee uniqueness in every TCP scenario.
- Retransmission and connection tracking do not implement every TCP lifecycle or concurrency case.
- Adding the 16-byte AES-GCM tag increases packet size, so MTU and fragmentation behavior need further work.
- The design has only been demonstrated in a controlled Linux setup.

A presentation should distinguish the behaviors the prototype demonstrates from these unresolved limitations.
