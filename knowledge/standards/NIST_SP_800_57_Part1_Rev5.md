# NIST Special Publication 800-57 Part 1 Revision 5
## Recommendation for Key Management: Part 1 – General

**Authority:** National Institute of Standards and Technology (NIST)  
**Publication Date:** May 2020  
**Status:** APPROVED / ACTIVE  
**Document Code:** NIST SP 800-57 Part 1 Rev. 5  
**URL:** https://csrc.nist.gov/publications/detail/sp/800-57/part-1/rev-5/final  

---

### Section 5.6.1 Comparable Algorithm Strengths and Key Sizes
NIST SP 800-57 Table 2 establishes the comparable security strengths across symmetric algorithms, finite-field cryptography (FFC / DH), and elliptic-curve cryptography (ECC):
- **112-bit Security Strength:** Minimum symmetric key size of 112 bits, MODP Group size of 2048 bits (Group 14), ECC key size of 224 bits. Legacy algorithms providing less than 112 bits (such as 1024-bit DH or 64-bit DES) are DISALLOWED.
- **128-bit Security Strength:** Symmetric algorithms with 128-bit keys (e.g., AES-128), MODP Group size of 3072 bits (Group 15), ECC key size of 256 bits (Curve P-256 / Group 19). Recommended for general enterprise and government data protection beyond 2030.
- **192-bit Security Strength:** Symmetric algorithms with 192-bit keys (e.g., AES-192), MODP Group size of 7680 bits, ECC key size of 384 bits (Curve P-384 / Group 20).
- **256-bit Security Strength:** Symmetric algorithms with 256-bit keys (e.g., AES-256), MODP Group size of 15360 bits, ECC key size of 512+ bits (Curve P-521 / Group 21). Mandated for high-assurance and National Security Systems (CNSA suite).
