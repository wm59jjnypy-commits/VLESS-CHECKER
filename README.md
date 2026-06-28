# VLESS-CHECKER
High-performance CLI tool for testing, analyzing, and scoring VLESS network endpoints 
# VLESS Checker

A high-performance CLI tool for testing and analyzing VLESS network endpoints.

It checks latency, TLS availability, geo-location, and assigns a quality score to each endpoint.

---

## 🚀 Features

- Parallel fetching of public VLESS sources
- TCP latency measurement (ping simulation)
- TLS handshake validation
- GeoIP lookup with caching
- Smart scoring system (0–11)
- Batch processing with progress tracking
- Resume support after interruption
- Rich CLI interface (progress bars, tables, panels)
- Export of working configurations
- Final structured report

---

## 🧠 Scoring system

Each endpoint is evaluated based on:

- Network latency
- Security type (reality / tls / none)
- TLS availability
- Transport type (ws / grpc bonus)
- SNI configuration
- Fingerprint support

Score range: **0–11**

---

## 📦 Installation

```bash
git clone https://github.com/X8XL8K8ST/vless-checker.git
cd vless-checker
pip install -r requirements.txt