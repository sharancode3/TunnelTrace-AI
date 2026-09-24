# NIST Special Publication 800-77 Revision 1
## Guide to IPsec VPNs

**Authority:** National Institute of Standards and Technology (NIST)  
**Publication Date:** December 2020  
**Status:** APPROVED / ACTIVE  
**Document Code:** NIST SP 800-77 Rev. 1  
**URL:** https://csrc.nist.gov/publications/detail/sp/800-77/rev-1/final  

---

### Section 5.1.1 Cryptographic Algorithms for Confidentiality (Encryption)
NIST SP 800-77 Rev. 1 mandates that IPsec VPNs SHALL use strong, standardized cryptographic algorithms.
Specifically:
- Authenticated Encryption with Associated Data (AEAD) algorithms, such as AES-GCM (Galois/Counter Mode) with 128-bit or 256-bit keys, are RECOMMENDED as preferred confidentiality algorithms for both IKEv2 and ESP.
- When CBC mode is utilized, AES-CBC with key sizes of 128 or 256 bits SHALL be used in conjunction with a separate cryptographically secure integrity algorithm (e.g., HMAC-SHA-256).
- Symmetric ciphers with block sizes smaller than 128 bits—including Data Encryption Standard (DES) and Triple-DES (3DES / TDEA)—SHALL NOT be used. 64-bit block ciphers are vulnerable to practical birthday-bound collision attacks (e.g., Sweet32) when processing high-volume encrypted traffic.
- Encryption key lengths of less than 128 bits SHALL NOT be used.

### Section 5.1.2 Cryptographic Algorithms for Integrity and Authentication
Data integrity and authentication algorithms protect IPsec messages against unauthorized tampering and spoofing:
- Secure Hash Algorithm 2 (SHA-2) algorithms (such as HMAC-SHA-256, HMAC-SHA-384, or HMAC-SHA-512) SHALL be used for non-AEAD integrity protection.
- MD5 and SHA-1 hashing algorithms SHALL NOT be used for integrity protection or digital signatures. Both MD5 and SHA-1 suffer from demonstrated collision weaknesses and are officially deprecated across federal information processing systems.
- When AEAD algorithms (such as AES-GCM) are negotiated, explicit integrity algorithms are integrated directly into the cipher transform; in such cases, integrity verification is cryptographically guaranteed by the 16-byte authentication tag (ICV).

### Section 5.1.3 Diffie-Hellman Key Exchange Groups
Diffie-Hellman (DH) and Elliptic Curve Diffie-Hellman (ECDH) key agreement protocols establish shared secrets across untrusted networks:
- Key establishment mechanisms SHALL provide a minimum of 112 bits of security strength (equivalent to MODP-2048, Group 14).
- VPN gateways SHALL support DH Group 14 (2048-bit MODP), Group 19 (256-bit Random ECP), Group 20 (384-bit Random ECP), and Group 21 (521-bit Random ECP).
- Legacy Diffie-Hellman groups with modulus sizes smaller than 2048 bits—including Group 1 (MODP-768), Group 2 (MODP-1024), and Group 5 (MODP-1536)—SHALL NOT be used due to vulnerability to precomputation attacks (e.g., Logjam).

### Section 5.2 IPsec Operational Modes
IPsec protocols support two primary operational modes:
- **Tunnel Mode:** Encapsulates the entire original IP packet within a new IP header and ESP header. Tunnel mode SHALL be used for all security gateway-to-gateway (site-to-site) connections and host-to-gateway (remote access) connections to conceal internal network addressing and topology.
- **Transport Mode:** Protects only the transport layer payload (and upper-layer protocols) while retaining the original IP header. Transport mode MAY be used exclusively for direct host-to-host communications where intermediate gateways do not inspect inner IP headers.

### Section 5.3 Key Management and Perfect Forward Secrecy (PFS)
To prevent retrospective traffic decryption in the event of long-term private key compromise:
- Organizations SHOULD mandate Perfect Forward Secrecy (PFS) on all Child Security Associations (Child SAs).
- When PFS is enabled, the IPsec endpoints SHALL perform an independent Diffie-Hellman key exchange during every CREATE_CHILD_SA or Child SA rekeying exchange, ensuring that ephemeral session keys cannot be derived from previous IKE SA keying material.
- If PFS is disabled, compromise of the parent IKE SA shared secret exposes all subsequent Child SA session keys.
