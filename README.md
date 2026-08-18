# chrono-forensics-triage# 🔍 Chrono-Forensics: Live Volatile Memory & Incident Triage Analyzer

A digital forensics and incident response (DFIR) triage engine designed to audit volatile host artifacts, identify unauthorized reverse shell sockets, flag memory execution from temporary paths, inspect persistence hooks, and generate cryptographically verified evidence bundles.

---

## ✨ Features
- **Volatile Network Inspection**: Detects outbound reverse shells and connections to non-standard remote ports.
- **Process Memory Path Auditing**: Flags binaries executing from writable system directories (e.g., `/dev/shm`, `/tmp`, `AppData\Local\Temp`).
- **Persistence Hook Scanner**: Parses crontabs and scheduled tasks for unauthorized network downloads or shell commands.
- **Chain of Custody Verification**: Computes SHA-256 digests over exportable forensic manifests for evidentiary integrity.
- **Zero Third-Party Dependencies**: Pure Python standard library implementation.

---

## 🚀 Quick Start
```bash
python3 chrono_triage.py
