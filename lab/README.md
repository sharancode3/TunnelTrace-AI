# TunnelTrace AI — Linux Namespace & strongSwan IPsec Testbed (Stage 2)
=============================================================================

This directory houses the isolated, Linux-native IPsec networking laboratory for **TunnelTrace AI** (Smart India Hackathon 2026, NTRO Problem Statement 26160 / PS 160).

The testbed provisions repeatable, deterministic IPsec VPN topologies using Linux Network Namespaces (`ip netns`), virtual Ethernet pairs (`veth`), Linux kernel XFRM, strongSwan 6.0.4+ (`charon` and `swanctl`), traffic control (`tc/netem`), and background `tcpdump` capture.

---

## 1. Architectural Model & Privilege Separation

TunnelTrace AI enforces strict privilege separation:

- **Class A (Unprivileged Application Plane):**
  FastAPI, Celery workers, PostgreSQL, Redis, future ML inference, and analytical dashboards run completely unprivileged without `CAP_NET_ADMIN`, `CAP_NET_RAW`, or Docker socket access.
- **Class B (Privileged Network Plane):**
  Isolated testbed lifecycle operations (namespace creation, veth wiring, routing, XFRM policy installation, strongSwan daemon control, tc netem, and lab packet capture) require Linux networking elevation (`root` / `CAP_NET_ADMIN`).
  - Class B interfaces are strictly typed, schema-validated, and allowlisted.
  - Zero arbitrary shell endpoints (`shell=True`, `eval`, and concatenation are prohibited).
  - Physical host network interfaces (`eth0`, `wlan0`, `enp*`, `docker0`) and host routes are strictly guarded against modification.

---

## 2. Supported Topologies & Capability Matrix

| Topology Family | Description | Namespaces Provisioned | Verified Protocols |
| :--- | :--- | :--- | :--- |
| **Family A: Site-to-Site Tunnel** | Gateway-to-Gateway IPsec protecting distinct client and server subnets. | 5 namespaces: `client`, `gw-a`, `wan`, `gw-b`, `server` with virtual WAN bridge `br-wan`. | IPv4 (`10.10.1.0/24` ↔ `10.10.2.0/24`), IPv6 (`fd00:10:1::/64` ↔ `fd00:10:2::/64`) |
| **Family B: Host-to-Host Transport** | Direct IPsec termination on communicating endpoints across untrusted WAN. | 3 namespaces: `peer-a`, `wan`, `peer-b` with virtual WAN bridge `br-wan`. | IPv4 (`198.51.100.1` ↔ `198.51.100.2`), IPv6 (`fd00:ba::1` ↔ `fd00:ba::2`) |

### Verified Scenario Profiles (`lab/scenarios/profiles/`)
1. `01_tunnel_ipv4_aes256gcm_pfs.yaml`: IKEv2, Tunnel Mode, IPv4, AES-256-GCM, DH Group 19 (ECP-256), PFS Enabled, Native ESP.
2. `02_tunnel_ipv4_aes256cbc_hmacsha256_nopfs.yaml`: IKEv2, Tunnel Mode, IPv4, AES-256-CBC, HMAC-SHA256, DH Group 14 (MODP-2048), PFS Disabled.
3. `03_transport_ipv4_aes256gcm.yaml`: IKEv2, Transport Mode, IPv4, AES-256-GCM, DH Group 19 (ECP-256).
4. `04_tunnel_ipv6_aes256gcm_pfs.yaml`: IKEv2, Tunnel Mode, IPv6, AES-256-GCM, DH Group 19 (ECP-256), PFS Enabled.
5. `05_tunnel_ipv4_netem_impairment.yaml`: IKEv2, Tunnel Mode, IPv4, AES-256-GCM with injected WAN delay (40ms) and jitter (5ms).
6. `06_tunnel_ipv4_natt.yaml`: IKEv2, Tunnel Mode, IPv4, AES-256-GCM with forced UDP/4500 encapsulation.

---

## 3. CLI Commands & Verified Operations

The testbed exposes a unified, typed command-line interface via `lab.cli`:

### Environment Pre-Flight Doctor
Probes host kernel, root elevation, network namespaces, XFRM support, tc/netem, tcpdump, and strongSwan binaries:
```bash
python -m lab.cli doctor
```

### List Registered Scenario Profiles
Inspects all scenario YAML files, validates their Pydantic schema, and prints SHA-256 configuration hashes:
```bash
python -m lab.cli list-profiles
```

### Execute Scenario End-to-End
Provisions namespaces, launches isolated charon daemons, establishes SAs, runs ICMP control traffic, captures WAN and plaintext PCAPs, records immutable `manifest.json`, and cleans up:
```bash
python -m lab.cli run-scenario 01_tunnel_ipv4_aes256gcm_pfs.yaml
```

### Emergency Stale Resource Purge
Safely scans for and purges any dangling `tt-*` testbed namespaces and releases the runtime concurrency lock:
```bash
python -m lab.cli clean-stale
```

---

## 4. Test Execution

### Unprivileged Unit Tests (33 tests, 0.14s)
Runs schema validation, command-builder security checks, physical interface rejection, and manifest serialization without needing root privileges:
```bash
pytest tests/unit backend/tests/unit
```

### Privileged Integration Tests (6 tests, 119s)
Executes real network namespace wiring, live strongSwan SA negotiations, kernel XFRM state validation, and live packet capture on authorized Linux/WSL2:
```bash
pytest tests/integration/test_lab_privileged.py -v
```

---

## 5. Storage Layout & Artifact Provenance

Every execution produces an isolated run bundle under `storage/lab/runs/<run_id>/`:
```
storage/lab/runs/<run_id>/
├── manifest.json                  # Machine-readable provenance manifest with SHA-256 digests
└── captures/
    ├── wan_encrypted.pcap         # Encrypted ESP & IKE packets captured on br-wan
    └── client_plaintext.pcap      # Plaintext ICMP packets captured on client private interface
```
Plaintext pre-shared keys and private keys are generated ephemerally at runtime and strictly excluded from manifests, logs, and Git.
