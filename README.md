# 🔥 Firewall-API
**Kernel-level API Abuse & DDoS Detector** *High-performance security without the proxy overhead.*

Firewall-API leverages **eBPF (XDP)** and **Go** to identify and drop malicious API traffic directly at the Network Interface Card (NIC) driver level. By enforcing rate limits in the kernel, we stop DDoS attacks before they ever reach your application or even the standard Linux networking stack.

---

## 🚀 Highlights
* **Zero-Copy Performance**: Drops packets in the kernel before memory allocation.
* **XDP-Powered**: Operates at the earliest possible point in the software stack.
* **Real-Time Analytics**: Go-based user-space agent provides a live view of blocked IPs.
* **Stealth Mode**: Dropped packets are invisible to `tcpdump` unless specifically traced.

## 🏗️ Architecture
The project is split into two layers:
1.  **Kernel-Space (`bpf/filter.c`)**: A C program that counts packets per source IP using an LRU Hash Map and returns `XDP_DROP` if thresholds are exceeded.
2.  **User-Space (`main.go`)**: A Go controller that loads the bytecode, attaches it to the NIC, and reads the kernel maps to report stats.

## 🛠️ Prerequisites
* **OS**: Linux (Kernel 5.7+ recommended for `bpf_link` support).
* **Dependencies**: `clang`, `llvm`, `make`, `linux-headers`.
* **Language**: Go 1.21+.

## 🚦 Quick Start

### 1. Installation (Arch Linux)
```bash
sudo pacman -S clang llvm linux-headers
go mod download
2. Build & Run
Bash
# This will generate BPF bindings, compile, and execute with sudo
make run
3. Simulate an Attack
In another terminal, flood your interface to trigger the rate limiter:

Bash
# Using hping3 to send 1000+ packets/sec
sudo hping3 --flood -S -p 80 127.0.0.1
📊 Roadmap
[ ] Payload Inspection: Parse HTTP headers in the kernel to block specific API paths.

[ ] Dynamic Thresholds: Allow the Go agent to update rate limits in real-time via BPF maps.

[ ] Prometheus Integration: Export drop-counts for Grafana dashboards.
