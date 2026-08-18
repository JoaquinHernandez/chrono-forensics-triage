import os
import sys
import json
import hashlib
import time
from datetime import datetime, timezone

# ANSI Color Codes
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[38;5;196m"
GREEN   = "\033[38;5;48m"
CYAN    = "\033[38;5;51m"
AMBER   = "\033[38;5;214m"
MAGENTA = "\033[38;5;201m"
GRAY    = "\033[38;5;242m"

BANNER = f"""{CYAN}{BOLD}
  ██████╗██╗  ██╗██████╗  ██████╗ ███╗   ██╗ ██████╗ 
 ██╔════╝██║  ██║██╔══██╗██╔═══██╗████╗  ██║██╔═══██╗
 ██║     ███████║██████╔╝██║   ██║██╔██╗ ██║██║   ██║
 ██║     ██╔══██║██╔══██╗██║   ██║██║╚██╗██║██║   ██║
 ╚██████╗██║  ██║██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝
  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ 
{RESET}{AMBER} » VOLATILE MEMORY & INCIDENT RESPONSE TRIAGE COLLECTOR «{RESET}
"""

class ChronoForensicsEngine:
    def __init__(self, policy_path="triage_policy.json", dump_path="mock_forensic_dump.json"):
        if not os.path.exists(policy_path) or not os.path.exists(dump_path):
            print(f"{RED}[-] Error: Missing triage policy or forensic dump file.{RESET}")
            sys.exit(1)

        with open(policy_path, "r") as f:
            self.policy = json.load(f)

        with open(dump_path, "r") as f:
            self.dump = json.load(f)

        self.suspicious_ports = self.policy.get("suspicious_ports", [])
        self.suspicious_paths = self.policy.get("suspicious_paths", [])
        self.persistence_keywords = self.policy.get("persistence_keywords", [])

    def calculate_sha256(self, content_str):
        return hashlib.sha256(content_str.encode("utf-8")).hexdigest()

    def run_investigation(self):
        print(BANNER)
        hostname = self.dump.get("hostname", "UNKNOWN-HOST")
        os_platform = self.dump.get("os_platform", "UNKNOWN-OS")
        case_id = f"{self.policy.get('investigation_case_prefix', 'IR')}-{int(time.time())}"

        print(f"{BOLD}Case ID:{RESET}         {CYAN}{case_id}{RESET}")
        print(f"{BOLD}Target Host:{RESET}     {hostname} ({os_platform})")
        print(f"{BOLD}Triage Started:{RESET}  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")

        phases = [
            "Acquiring volatile memory handles & process table",
            "Parsing network sockets and active foreign connections",
            "Inspecting execution paths against unprivileged temporary directories",
            "Scanning crontabs & scheduled persistence hooks",
            "Generating cryptographic chain-of-custody checksums"
        ]
        for phase in phases:
            time.sleep(0.25)
            print(f"  {CYAN}▸{RESET} {phase}...")

        print("\n" + "=" * 85 + "\n")
        print(f"{BOLD}{'ARTIFACT TYPE':<18} {'IDENTIFIER':<24} {'SEVERITY':<12} {'FORENSIC FINDING'}{RESET}")
        print("-" * 85)

        findings = []

        # 1. Inspect Active Network Sockets
        for sock in self.dump.get("active_sockets", []):
            foreign = sock.get("foreign_addr", "")
            port = int(foreign.split(":")[-1]) if ":" in foreign and foreign.split(":")[-1].isdigit() else 0

            if port in self.suspicious_ports:
                findings.append({
                    "type": "Network Socket",
                    "id": f"PID {sock['pid']} ({sock['process']})",
                    "severity": "CRITICAL",
                    "detail": f"Established reverse shell socket to C2 endpoint: {foreign}"
                })
                print(f"{'Network Socket':<18} {f'PID {sock[\"pid\"]} ({sock[\"process\"]})':<24} {RED}{'CRITICAL':<12}{RESET} Reverse Connection: {foreign}")

        # 2. Inspect Running Processes and Binary Paths
        for proc in self.dump.get("running_processes", []):
            exe = proc.get("exe_path", "")
            if any(bad_path in exe for bad_path in self.suspicious_paths):
                findings.append({
                    "type": "Process Execution",
                    "id": f"PID {proc['pid']} ({proc['name']})",
                    "severity": "CRITICAL",
                    "detail": f"Binary executed from writable volatile path: {exe}"
                })
                print(f"{'Process Exec':<18} {f'PID {proc[\"pid\"]} ({proc[\"name\"]})':<24} {RED}{'CRITICAL':<12}{RESET} Executing from {exe}")

        # 3. Inspect Persistence Mechanisms
        for p in self.dump.get("persistence_entries", []):
            entry = p.get("entry", "")
            if any(k in entry for k in self.persistence_keywords):
                findings.append({
                    "type": "Persistence Hook",
                    "id": p.get("source", "Cron/Task"),
                    "severity": "HIGH",
                    "detail": f"Suspicious scheduled command string: {entry}"
                })
                print(f"{'Persistence':<18} {p.get('source', 'Cron')[:24]:<24} {AMBER}{'HIGH':<12}{RESET} Malicious scheduled payload")

        print("=" * 85)

        # Generate Evidence Manifest
        evidence_data = {
            "case_id": case_id,
            "target_host": hostname,
            "os": os_platform,
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "findings_count": len(findings),
            "findings": findings
        }
        manifest_raw = json.dumps(evidence_data, indent=2)
        manifest_hash = self.calculate_sha256(manifest_raw)

        bundle_filename = f"triage_manifest_{case_id}.json"
        with open(bundle_filename, "w") as f:
            f.write(manifest_raw)

        print(f"\n{BOLD}Triage Results:{RESET} Flagged {RED}{len(findings)}{RESET} critical forensic anomalies.")
        print(f"{GREEN}[✓] Forensic Evidence Manifest Exported:{RESET} {BOLD}{bundle_filename}{RESET}")
        print(f"{BOLD}Chain-of-Custody SHA-256:{RESET}\n  {GRAY}{manifest_hash}{RESET}\n")

if __name__ == "__main__":
    engine = ChronoForensicsEngine()
    engine.run_investigation()
