"""
Realistic network alert scenarios for all three tasks.

All data is deterministic and hardcoded — no randomness, same inputs → same outputs.
IPs, ports, timestamps, and descriptions reflect real-world NOC patterns.
"""
from __future__ import annotations

from .models import NetworkAlert, SeverityLevel


def _ts(hour: int, minute: int, second: int, day: int = 15) -> str:
    return f"2024-01-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}Z"


# ─────────────────────────────────────────────
# EASY TASK — "alert-classify"  (5 alerts, 1 step)
# ─────────────────────────────────────────────

EASY_ALERTS: list[NetworkAlert] = [
    NetworkAlert(
        alert_id="A001",
        timestamp=_ts(14, 30, 5),
        source_ip="194.165.16.10",
        dest_ip="10.0.1.15",
        source_port=49521,
        dest_port=22,
        protocol="TCP",
        bytes_transferred=2048,
        packets_count=1523,
        duration_seconds=12.3,
        alert_type_raw="Connection sweep detected — multiple ports",
        description=(
            "Source IP 194.165.16.10 probed 512 distinct ports on 10.0.1.15 within 30 seconds. "
            "SYN packets sent without completing three-way handshake. "
            "IP matches known-scanner database entry (threat feed score: 8.2). "
            "Geo: Russia. Same IP observed scanning three other ASNs in past 48h."
        ),
        severity=SeverityLevel.HIGH,
        frequency=1,
        geo_location="RU",
        threat_score=8.2,
        tags=["syn-sweep", "known-scanner", "threat-intel-match"],
    ),
    NetworkAlert(
        alert_id="A002",
        timestamp=_ts(14, 31, 10),
        source_ip="216.58.194.78",
        dest_ip="10.0.1.42",
        source_port=443,
        dest_port=52341,
        protocol="TCP",
        bytes_transferred=45678,
        packets_count=89,
        duration_seconds=2.1,
        alert_type_raw="HTTPS inbound session",
        description=(
            "Standard HTTPS session from Google LLC (216.58.194.78, AS15169) to workstation 10.0.1.42. "
            "TLS 1.3 with valid certificate chain. Traffic pattern consistent with Google Search "
            "and Analytics payloads. No anomalous headers, no payload obfuscation detected."
        ),
        severity=SeverityLevel.INFO,
        frequency=1,
        geo_location="US",
        threat_score=0.1,
        tags=["https", "google", "benign"],
    ),
    NetworkAlert(
        alert_id="A003",
        timestamp=_ts(14, 32, 0),
        source_ip="0.0.0.0",
        dest_ip="10.0.1.1",
        source_port=0,
        dest_port=80,
        protocol="UDP",
        bytes_transferred=5_242_880,
        packets_count=85_000,
        duration_seconds=60.0,
        alert_type_raw="High-volume inbound traffic anomaly — UDP flood",
        description=(
            "UDP flood targeting 10.0.1.1:80 from 3,847 distinct source IPs. "
            "Avg packet size 64 bytes, sustained rate 1,416 pkt/s — 40x above 7-day baseline. "
            "Sources distributed: CN (34%), RU (22%), BR (18%), UA (14%), other (12%). "
            "Matches DDoS botnet signature DB-2024-441. Gateway CPU at 94%, drop rate rising."
        ),
        severity=SeverityLevel.CRITICAL,
        frequency=85_000,
        geo_location="MULTIPLE",
        threat_score=9.5,
        tags=["ddos", "udp-flood", "botnet", "volumetric"],
    ),
    NetworkAlert(
        alert_id="A004",
        timestamp=_ts(14, 33, 15),
        source_ip="45.142.212.100",
        dest_ip="10.0.1.20",
        source_port=54321,
        dest_port=22,
        protocol="TCP",
        bytes_transferred=2_048,
        packets_count=156,
        duration_seconds=45.2,
        alert_type_raw="Authentication failure threshold exceeded — SSH",
        description=(
            "IP 45.142.212.100 generated 156 failed SSH authentication attempts against 10.0.1.20 "
            "in 45 seconds. Usernames attempted: root, admin, ubuntu, deploy, git, postgres, backup. "
            "Credential-spray pattern (low-and-slow dictionary). Geo: China. "
            "IP on threat intel list: known credential-stuffing actor, active since 2023-09."
        ),
        severity=SeverityLevel.HIGH,
        frequency=156,
        geo_location="CN",
        threat_score=8.8,
        tags=["brute-force", "ssh", "credential-spray", "threat-intel-match"],
    ),
    NetworkAlert(
        alert_id="A005",
        timestamp=_ts(14, 34, 22),
        source_ip="10.0.1.35",
        dest_ip="151.101.1.140",
        source_port=51234,
        dest_port=80,
        protocol="TCP",
        bytes_transferred=12_345,
        packets_count=23,
        duration_seconds=1.8,
        alert_type_raw="HTTP outbound — low risk score",
        description=(
            "Standard HTTP session from workstation 10.0.1.35 to Fastly CDN node (151.101.1.140). "
            "GET requests for static assets (CSS, JS, PNG). Content fingerprinted as Reddit CDN assets. "
            "Normal browser user-agent (Chrome 120). No malicious payloads or obfuscation."
        ),
        severity=SeverityLevel.INFO,
        frequency=1,
        geo_location="US",
        threat_score=0.2,
        tags=["http", "cdn", "benign"],
    ),
]

# Ground truth for grader — acceptable_* dicts give partial-credit scores per response
EASY_GROUND_TRUTH: dict = {
    "classifications": {
        "A001": "port_scan",
        "A002": "normal",
        "A003": "ddos",
        "A004": "brute_force",
        "A005": "normal",
    },
    "actions": {
        "A001": "block",
        "A002": "ignore",
        "A003": "escalate",
        "A004": "block",
        "A005": "ignore",
    },
    "is_threat": {"A001": True, "A002": False, "A003": True, "A004": True, "A005": False},
    "is_critical": {"A001": False, "A002": False, "A003": True, "A004": False, "A005": False},
    # Per-response action scores: 1.0 = perfect, 0.5 = partial, negative = penalty
    "acceptable_actions": {
        "A001": {"block": 1.0, "escalate": 0.6, "rate_limit": 0.3, "investigate": 0.2, "monitor": 0.1, "ignore": -1.0},
        "A002": {"ignore": 1.0, "monitor": 0.5, "investigate": 0.2, "rate_limit": -0.3, "escalate": -0.3, "block": -1.5},
        "A003": {"escalate": 1.0, "block": 0.5, "rate_limit": 0.2, "investigate": 0.2, "monitor": 0.1, "ignore": -1.0},
        "A004": {"block": 1.0, "escalate": 0.7, "rate_limit": 0.4, "investigate": 0.2, "monitor": 0.1, "ignore": -0.8},
        "A005": {"ignore": 1.0, "monitor": 0.5, "investigate": 0.2, "rate_limit": -0.3, "escalate": -0.3, "block": -1.5},
    },
    # Per-response classification scores
    "acceptable_classifications": {
        "A001": {"port_scan": 1.0, "reconnaissance": 0.6, "unknown": 0.2},
        "A002": {"normal": 1.0},
        "A003": {"ddos": 1.0},
        "A004": {"brute_force": 1.0, "reconnaissance": 0.3},
        "A005": {"normal": 1.0},
    },
}


# ─────────────────────────────────────────────
# MEDIUM TASK — "incident-response"  (10 alerts, 5 steps × 2 alerts)
# ─────────────────────────────────────────────

MEDIUM_ALERT_BATCHES: list[list[NetworkAlert]] = [
    # Step 1 — Batch 0
    [
        NetworkAlert(
            alert_id="M001",
            timestamp=_ts(3, 47, 12),
            source_ip="10.0.1.99",
            dest_ip="10.0.1.5",
            source_port=51020,
            dest_port=22,
            protocol="TCP",
            bytes_transferred=4_096,
            packets_count=42,
            duration_seconds=8.2,
            alert_type_raw="After-hours privileged login — internal",
            description=(
                "User 'devops-svc' authenticated via SSH from 10.0.1.99 to internal jump host 10.0.1.5 "
                "at 03:47 local time. Account last logged in at 17:22 yesterday. "
                "No scheduled maintenance window active. SIEM flagged unusual hour. "
                "No failed attempts before success — valid credentials used."
            ),
            severity=SeverityLevel.MEDIUM,
            frequency=1,
            geo_location="INTERNAL",
            threat_score=4.5,
            tags=["after-hours", "privileged-account", "ssh", "anomalous-time"],
        ),
        NetworkAlert(
            alert_id="M002",
            timestamp=_ts(3, 47, 55),
            source_ip="10.0.1.5",
            dest_ip="8.8.8.8",
            source_port=52100,
            dest_port=53,
            protocol="UDP",
            bytes_transferred=128,
            packets_count=2,
            duration_seconds=0.05,
            alert_type_raw="DNS query — routine resolution",
            description=(
                "Standard DNS A-record query from jump host 10.0.1.5 to Google Public DNS (8.8.8.8). "
                "Query for 'api.github.com'. Response: 140.82.114.5. "
                "Query length normal (42 bytes). No tunneling indicators. Routine outbound resolution."
            ),
            severity=SeverityLevel.INFO,
            frequency=1,
            geo_location="US",
            threat_score=0.3,
            tags=["dns", "benign"],
        ),
    ],
    # Step 2 — Batch 1
    [
        NetworkAlert(
            alert_id="M003",
            timestamp=_ts(3, 49, 0),
            source_ip="45.142.212.100",
            dest_ip="10.0.1.20",
            source_port=55010,
            dest_port=22,
            protocol="TCP",
            bytes_transferred=512,
            packets_count=8,
            duration_seconds=3.1,
            alert_type_raw="SSH authentication failure — attempt 1",
            description=(
                "Single failed SSH authentication to 10.0.1.20 from 45.142.212.100 (CN). "
                "Username 'root' tried. Connection reset after failure. "
                "First occurrence from this IP — monitoring threshold not yet reached."
            ),
            severity=SeverityLevel.LOW,
            frequency=1,
            geo_location="CN",
            threat_score=3.5,
            tags=["ssh-fail", "external-ip"],
        ),
        NetworkAlert(
            alert_id="M004",
            timestamp=_ts(3, 49, 30),
            source_ip="194.165.16.10",
            dest_ip="10.0.1.0",
            source_port=40120,
            dest_port=443,
            protocol="TCP",
            bytes_transferred=4_096,
            packets_count=412,
            duration_seconds=8.7,
            alert_type_raw="Subnet port sweep — HTTPS probe",
            description=(
                "IP 194.165.16.10 (RU, known scanner) swept all 254 hosts in 10.0.1.0/24 on port 443. "
                "SYN-only probes, no connections completed. 412 packets in 8.7 s. "
                "Same IP triggered A001 (port scan on 10.0.1.15) earlier this session."
            ),
            severity=SeverityLevel.HIGH,
            frequency=1,
            geo_location="RU",
            threat_score=8.5,
            tags=["port-scan", "subnet-sweep", "known-scanner", "threat-intel-match"],
            related_alert_ids=["A001"],
        ),
    ],
    # Step 3 — Batch 2
    [
        NetworkAlert(
            alert_id="M005",
            timestamp=_ts(3, 51, 45),
            source_ip="45.142.212.100",
            dest_ip="10.0.1.20",
            source_port=55011,
            dest_port=22,
            protocol="TCP",
            bytes_transferred=2_560,
            packets_count=48,
            duration_seconds=12.0,
            alert_type_raw="SSH brute-force — 12 failures in 2 min (same IP as M003)",
            description=(
                "IP 45.142.212.100 (same as M003) has now made 12 failed SSH attempts to 10.0.1.20 "
                "in under 2 minutes. Usernames: root, admin, ubuntu, deploy, svc-backup. "
                "Escalating frequency — now 4 attempts/minute. Pattern matches automated credential spray."
            ),
            severity=SeverityLevel.HIGH,
            frequency=12,
            geo_location="CN",
            threat_score=8.0,
            tags=["brute-force", "ssh", "credential-spray", "escalating"],
            related_alert_ids=["M003"],
        ),
        NetworkAlert(
            alert_id="M006",
            timestamp=_ts(3, 52, 10),
            source_ip="10.0.1.30",
            dest_ip="103.41.167.90",
            source_port=49200,
            dest_port=443,
            protocol="TCP",
            bytes_transferred=524_288_000,
            packets_count=375_000,
            duration_seconds=420.0,
            alert_type_raw="Large outbound data transfer to unknown external IP",
            description=(
                "Workstation 10.0.1.30 transferred 500 MB to 103.41.167.90 (HK, no reverse DNS, "
                "not in approved cloud egress list) over 7 minutes. "
                "TLS 1.2 session with self-signed certificate. Transfer rate: 1.19 MB/s sustained. "
                "No user session active on 10.0.1.30 at this time. Geo: Hong Kong."
            ),
            severity=SeverityLevel.CRITICAL,
            frequency=1,
            geo_location="HK",
            threat_score=9.1,
            tags=["data-exfiltration", "large-transfer", "no-user-session", "unknown-external"],
        ),
    ],
    # Step 4 — Batch 3
    [
        NetworkAlert(
            alert_id="M007",
            timestamp=_ts(3, 54, 0),
            source_ip="10.0.1.45",
            dest_ip="93.184.216.34",
            source_port=52800,
            dest_port=443,
            protocol="TCP",
            bytes_transferred=18_432,
            packets_count=31,
            duration_seconds=2.4,
            alert_type_raw="HTTPS outbound — low risk",
            description=(
                "Normal HTTPS session from workstation 10.0.1.45 to example.com (93.184.216.34, IANA). "
                "18 KB content download, valid certificate, standard browser headers. "
                "Consistent with developer documentation browsing. No anomalies."
            ),
            severity=SeverityLevel.INFO,
            frequency=1,
            geo_location="US",
            threat_score=0.1,
            tags=["https", "benign"],
        ),
        NetworkAlert(
            alert_id="M008",
            timestamp=_ts(3, 54, 33),
            source_ip="10.0.1.22",
            dest_ip="91.92.248.151",
            source_port=49800,
            dest_port=8443,
            protocol="TCP",
            bytes_transferred=10_240,
            packets_count=280,
            duration_seconds=310.0,
            alert_type_raw="Suspicious C2 beaconing — known malware infrastructure",
            description=(
                "Host 10.0.1.22 making periodic small-packet connections to 91.92.248.151:8443. "
                "Beacon interval: ~60 seconds. Average payload 36 bytes. "
                "Destination IP matches Cobalt Strike C2 infrastructure (threat intel DB, confidence: HIGH). "
                "TLS with JA3 fingerprint matching known RAT. Host 10.0.1.22 shows no user activity."
            ),
            severity=SeverityLevel.CRITICAL,
            frequency=5,
            geo_location="NL",
            threat_score=9.8,
            tags=["c2-beacon", "cobalt-strike", "malware", "known-bad-ip", "ja3-match"],
        ),
    ],
    # Step 5 — Batch 4
    [
        NetworkAlert(
            alert_id="M009",
            timestamp=_ts(3, 56, 5),
            source_ip="10.0.1.22",
            dest_ip="10.0.1.50",
            source_port=49900,
            dest_port=445,
            protocol="TCP",
            bytes_transferred=102_400,
            packets_count=420,
            duration_seconds=15.3,
            alert_type_raw="Lateral movement — SMB from potentially compromised host",
            description=(
                "Host 10.0.1.22 (flagged in M008 as C2-beaconing) initiated SMB connections to "
                "10.0.1.50 on port 445. 100 KB transferred. SMB enumeration pattern: "
                "IPC$ share probe, ADMIN$ probe. Consistent with post-exploitation lateral movement. "
                "10.0.1.50 is a file server with sensitive data."
            ),
            severity=SeverityLevel.CRITICAL,
            frequency=1,
            geo_location="INTERNAL",
            threat_score=9.9,
            tags=["lateral-movement", "smb", "post-exploitation", "compromised-host"],
            related_alert_ids=["M008"],
        ),
        NetworkAlert(
            alert_id="M010",
            timestamp=_ts(3, 56, 45),
            source_ip="10.0.1.99",
            dest_ip="10.0.1.5",
            source_port=51021,
            dest_port=22,
            protocol="TCP",
            bytes_transferred=8_192,
            packets_count=85,
            duration_seconds=22.5,
            alert_type_raw="Privilege escalation — sudo log deletion attempt",
            description=(
                "Session from 10.0.1.99 (same IP as after-hours login M001) on jump host 10.0.1.5 "
                "executed: 'sudo truncate -s 0 /var/log/auth.log' and 'sudo rm -f /var/log/syslog*'. "
                "Log deletion is a known defense evasion technique. "
                "Commands run 9 minutes after initial login. Privilege escalation confirmed."
            ),
            severity=SeverityLevel.CRITICAL,
            frequency=1,
            geo_location="INTERNAL",
            threat_score=9.7,
            tags=["privilege-escalation", "log-deletion", "defense-evasion"],
            related_alert_ids=["M001"],
        ),
    ],
]

# Flatten for reference
MEDIUM_ALERTS: list[NetworkAlert] = [a for batch in MEDIUM_ALERT_BATCHES for a in batch]

MEDIUM_GROUND_TRUTH: dict = {
    "classifications": {
        "M001": "reconnaissance",
        "M002": "normal",
        "M003": "brute_force",
        "M004": "port_scan",
        "M005": "brute_force",
        "M006": "data_exfiltration",
        "M007": "normal",
        "M008": "malware",
        "M009": "lateral_movement",
        "M010": "privilege_escalation",
    },
    "actions": {
        "M001": "investigate",
        "M002": "ignore",
        "M003": "rate_limit",     # First occurrence — rate_limit is prudent, not yet block
        "M004": "block",
        "M005": "block",          # Repeated brute force — now block
        "M006": "escalate",
        "M007": "ignore",
        "M008": "block",
        "M009": "block",
        "M010": "escalate",
    },
    "is_threat": {
        "M001": True, "M002": False, "M003": True, "M004": True,
        "M005": True, "M006": True, "M007": False, "M008": True,
        "M009": True, "M010": True,
    },
    "is_critical": {
        "M001": False, "M002": False, "M003": False, "M004": False,
        "M005": False, "M006": True, "M007": False, "M008": True,
        "M009": True, "M010": True,
    },
    "acceptable_actions": {
        "M001": {"investigate": 1.0, "monitor": 0.7, "escalate": 0.6, "rate_limit": 0.2, "ignore": -0.3, "block": -0.8},
        "M002": {"ignore": 1.0, "monitor": 0.5, "investigate": 0.2, "rate_limit": -0.2, "block": -1.5, "escalate": -0.2},
        "M003": {"rate_limit": 1.0, "block": 0.7, "investigate": 0.5, "monitor": 0.4, "escalate": 0.4, "ignore": -0.5},
        "M004": {"block": 1.0, "escalate": 0.6, "rate_limit": 0.3, "monitor": 0.1, "investigate": 0.2, "ignore": -0.8},
        "M005": {"block": 1.0, "escalate": 0.7, "rate_limit": 0.2, "investigate": 0.1, "monitor": 0.0, "ignore": -1.0},
        "M006": {"escalate": 1.0, "block": 0.6, "investigate": 0.4, "monitor": 0.2, "rate_limit": 0.1, "ignore": -1.0},
        "M007": {"ignore": 1.0, "monitor": 0.5, "investigate": 0.2, "rate_limit": -0.2, "block": -1.5, "escalate": -0.2},
        "M008": {"block": 1.0, "escalate": 0.8, "investigate": 0.3, "rate_limit": 0.1, "monitor": 0.0, "ignore": -1.0},
        "M009": {"block": 1.0, "escalate": 0.8, "investigate": 0.3, "rate_limit": 0.1, "monitor": 0.0, "ignore": -1.0},
        "M010": {"escalate": 1.0, "block": 0.6, "investigate": 0.4, "monitor": 0.1, "rate_limit": 0.0, "ignore": -1.0},
    },
    "acceptable_classifications": {
        "M001": {"reconnaissance": 1.0, "unknown": 0.4, "normal": -0.2},
        "M002": {"normal": 1.0},
        "M003": {"brute_force": 1.0, "reconnaissance": 0.4, "unknown": 0.2},
        "M004": {"port_scan": 1.0, "reconnaissance": 0.7},
        "M005": {"brute_force": 1.0},
        "M006": {"data_exfiltration": 1.0, "malware": 0.4, "unknown": 0.2},
        "M007": {"normal": 1.0},
        "M008": {"malware": 1.0, "reconnaissance": 0.3},
        "M009": {"lateral_movement": 1.0, "malware": 0.5},
        "M010": {"privilege_escalation": 1.0, "lateral_movement": 0.4, "malware": 0.3},
    },
}


# ─────────────────────────────────────────────
# HARD TASK — "triage-under-load"  (20 alerts, up to 3 steps)
# ─────────────────────────────────────────────

HARD_ALERTS: list[NetworkAlert] = [
    # H001 — CRITICAL: C2 beaconing
    NetworkAlert(
        alert_id="H001",
        timestamp=_ts(2, 15, 3),
        source_ip="10.0.1.30",
        dest_ip="91.92.248.151",
        source_port=49200,
        dest_port=8443,
        protocol="TCP",
        bytes_transferred=8_192,
        packets_count=210,
        duration_seconds=240.0,
        alert_type_raw="Periodic outbound beaconing — C2 suspected",
        description=(
            "Host 10.0.1.30 beaconing to 91.92.248.151:8443 every ~58 seconds. "
            "Payload: 39 bytes avg. JA3 hash matches Cobalt Strike malleable C2 profile. "
            "Destination in Cobalt Strike tracker (confidence: 97%). No user session on host."
        ),
        severity=SeverityLevel.CRITICAL,
        frequency=4,
        geo_location="NL",
        threat_score=9.9,
        tags=["c2", "cobalt-strike", "beacon", "known-bad-ip"],
    ),
    # H002 — RED HERRING: Legitimate cloud backup (looks like data exfil)
    NetworkAlert(
        alert_id="H002",
        timestamp=_ts(2, 15, 30),
        source_ip="10.0.1.100",
        dest_ip="54.230.12.8",
        source_port=49300,
        dest_port=443,
        protocol="TCP",
        bytes_transferred=2_147_483_648,
        packets_count=1_500_000,
        duration_seconds=1_800.0,
        alert_type_raw="Large outbound HTTPS transfer",
        description=(
            "Host 10.0.1.100 (backup-server) transferred 2 GB to 54.230.12.8 (Amazon AWS S3, us-east-1). "
            "Initiated at 02:15 — matches scheduled nightly backup window (02:00–04:00 documented). "
            "Destination bucket ARN verified in approved cloud egress list. "
            "TLS with valid AWS certificate. Backup-agent process confirmed running."
        ),
        severity=SeverityLevel.INFO,
        frequency=1,
        geo_location="US",
        threat_score=1.2,
        tags=["aws-s3", "backup", "scheduled", "approved-egress"],
    ),
    # H003 — HIGH: SSH brute force
    NetworkAlert(
        alert_id="H003",
        timestamp=_ts(2, 16, 0),
        source_ip="185.220.101.45",
        dest_ip="10.0.1.20",
        source_port=58441,
        dest_port=22,
        protocol="TCP",
        bytes_transferred=3_072,
        packets_count=195,
        duration_seconds=58.0,
        alert_type_raw="SSH brute-force — Tor exit node",
        description=(
            "Tor exit node 185.220.101.45 made 195 failed SSH login attempts to 10.0.1.20 in 58 seconds. "
            "Usernames: root, admin, pi, ubuntu, ftpuser. Password list matches rockyou subset. "
            "Tor exit node confirmed via ExoneraTor DB. Rate: 3.4 attempts/second."
        ),
        severity=SeverityLevel.HIGH,
        frequency=195,
        geo_location="DE",
        threat_score=8.7,
        tags=["brute-force", "ssh", "tor", "known-bad-ip"],
    ),
    # H004 — HIGH: Subnet port scan
    NetworkAlert(
        alert_id="H004",
        timestamp=_ts(2, 16, 20),
        source_ip="194.165.16.10",
        dest_ip="10.0.0.0",
        source_port=41000,
        dest_port=0,
        protocol="TCP",
        bytes_transferred=10_240,
        packets_count=2_048,
        duration_seconds=20.5,
        alert_type_raw="Network-wide port scan — top-100 ports",
        description=(
            "IP 194.165.16.10 (RU, known scanner feed) swept top-100 ports across entire "
            "10.0.0.0/16 subnet in 20 seconds. SYN-only. Discovered open ports logged. "
            "Previous activity: A001, M004. Third sighting in 2 hours — escalating aggression."
        ),
        severity=SeverityLevel.HIGH,
        frequency=1,
        geo_location="RU",
        threat_score=8.5,
        tags=["port-scan", "network-sweep", "known-scanner", "repeat-offender"],
        related_alert_ids=["A001", "M004"],
    ),
    # H005 — NORMAL: Outbound HTTPS to CDN
    NetworkAlert(
        alert_id="H005",
        timestamp=_ts(2, 17, 0),
        source_ip="10.0.1.12",
        dest_ip="172.217.14.196",
        source_port=53200,
        dest_port=443,
        protocol="TCP",
        bytes_transferred=32_768,
        packets_count=56,
        duration_seconds=3.2,
        alert_type_raw="HTTPS outbound — Google CDN",
        description=(
            "Workstation 10.0.1.12 HTTPS session to Google CDN (172.217.14.196, AS15169). "
            "32 KB download. Content-type: application/javascript (Google Maps API). "
            "Valid TLS chain. Normal browser headers. Routine web browsing."
        ),
        severity=SeverityLevel.INFO,
        frequency=1,
        geo_location="US",
        threat_score=0.1,
        tags=["https", "google-cdn", "benign"],
    ),
    # H006 — CRITICAL: Data exfiltration
    NetworkAlert(
        alert_id="H006",
        timestamp=_ts(2, 17, 30),
        source_ip="10.0.1.22",
        dest_ip="103.41.167.90",
        source_port=49800,
        dest_port=443,
        protocol="TCP",
        bytes_transferred=2_097_152_000,
        packets_count=1_500_000,
        duration_seconds=900.0,
        alert_type_raw="Massive outbound transfer — unapproved destination",
        description=(
            "Host 10.0.1.22 transferred 2 GB to 103.41.167.90 (HK, no PTR record, "
            "not in approved egress list). Self-signed TLS. No user session. "
            "Transfer rate 2.3 MB/s sustained for 15 minutes. "
            "Host 10.0.1.22 is HR workstation with access to employee PII. DLP alert: PII keywords detected."
        ),
        severity=SeverityLevel.CRITICAL,
        frequency=1,
        geo_location="HK",
        threat_score=9.8,
        tags=["data-exfiltration", "dlp-alert", "pii", "unapproved-destination", "no-user-session"],
    ),
    # H007 — CRITICAL: Lateral movement from C2 host
    NetworkAlert(
        alert_id="H007",
        timestamp=_ts(2, 18, 0),
        source_ip="10.0.1.30",
        dest_ip="10.0.1.50",
        source_port=49500,
        dest_port=445,
        protocol="TCP",
        bytes_transferred=204_800,
        packets_count=850,
        duration_seconds=24.0,
        alert_type_raw="SMB lateral movement from C2 host",
        description=(
            "Host 10.0.1.30 (C2-beaconing per H001) initiated SMB sessions to 10.0.1.50 (file server). "
            "SMB enumeration: IPC$, ADMIN$, C$, HR_SHARE. 200 KB transferred inbound. "
            "Attempted authentication with service account credentials. "
            "Pattern matches BloodHound/SharpHound AD enumeration."
        ),
        severity=SeverityLevel.CRITICAL,
        frequency=1,
        geo_location="INTERNAL",
        threat_score=9.9,
        tags=["lateral-movement", "smb", "ad-enumeration", "post-exploitation"],
        related_alert_ids=["H001"],
    ),
    # H008 — NORMAL: DNS lookup
    NetworkAlert(
        alert_id="H008",
        timestamp=_ts(2, 18, 30),
        source_ip="10.0.1.5",
        dest_ip="1.1.1.1",
        source_port=51000,
        dest_port=53,
        protocol="UDP",
        bytes_transferred=82,
        packets_count=2,
        duration_seconds=0.04,
        alert_type_raw="DNS query — routine",
        description=(
            "Standard DNS A-record query to Cloudflare resolver (1.1.1.1). "
            "Query: 'www.github.com'. Response: 140.82.114.4. "
            "Normal query size (41 bytes). No encoding anomalies. Routine resolution."
        ),
        severity=SeverityLevel.INFO,
        frequency=1,
        geo_location="US",
        threat_score=0.1,
        tags=["dns", "benign"],
    ),
    # H009 — HIGH: DDoS attempt against internal DNS
    NetworkAlert(
        alert_id="H009",
        timestamp=_ts(2, 19, 0),
        source_ip="0.0.0.0",
        dest_ip="10.0.1.53",
        source_port=0,
        dest_port=53,
        protocol="UDP",
        bytes_transferred=786_432,
        packets_count=12_000,
        duration_seconds=30.0,
        alert_type_raw="DNS amplification attack — internal resolver targeted",
        description=(
            "Internal DNS resolver 10.0.1.53 receiving 400 pkt/s from 892 spoofed external IPs. "
            "ANY-record queries (amplification vector). Server response rate 8x inbound. "
            "DNS resolver showing 78% CPU. Matches DNS amplification pattern."
        ),
        severity=SeverityLevel.HIGH,
        frequency=12_000,
        geo_location="MULTIPLE",
        threat_score=8.2,
        tags=["ddos", "dns-amplification", "volumetric"],
    ),
    # H010 — AMBIGUOUS: Internal security scanner (classify as reconnaissance, investigate)
    NetworkAlert(
        alert_id="H010",
        timestamp=_ts(2, 19, 30),
        source_ip="10.0.1.254",
        dest_ip="10.0.0.0",
        source_port=40000,
        dest_port=22,
        protocol="TCP",
        bytes_transferred=5_120,
        packets_count=512,
        duration_seconds=15.0,
        alert_type_raw="Internal subnet scan — SSH probe",
        description=(
            "Host 10.0.1.254 scanned all 254 hosts in 10.0.0.0/24 for open SSH port. "
            "Source is in the 'security-tools' VLAN. No threat intel match. "
            "Could be authorized vulnerability scan or insider reconnaissance. "
            "No maintenance window logged for this activity."
        ),
        severity=SeverityLevel.MEDIUM,
        frequency=1,
        geo_location="INTERNAL",
        threat_score=4.0,
        tags=["internal-scan", "ssh", "ambiguous", "security-vlan"],
    ),
    # H011 — CRITICAL: Privilege escalation
    NetworkAlert(
        alert_id="H011",
        timestamp=_ts(2, 20, 0),
        source_ip="10.0.1.22",
        dest_ip="10.0.1.20",
        source_port=49900,
        dest_port=22,
        protocol="TCP",
        bytes_transferred=12_288,
        packets_count=130,
        duration_seconds=35.0,
        alert_type_raw="Privilege escalation — /etc/sudoers modification via SSH",
        description=(
            "Host 10.0.1.22 (previously flagged for data exfil H006) SSH'd to 10.0.1.20 and "
            "executed: 'echo \"ALL ALL=(ALL) NOPASSWD: ALL\" >> /etc/sudoers'. "
            "Command logged via auditd. SIEM correlation: same host as H006 data exfil. "
            "Attacker establishing persistence with root-level access."
        ),
        severity=SeverityLevel.CRITICAL,
        frequency=1,
        geo_location="INTERNAL",
        threat_score=10.0,
        tags=["privilege-escalation", "sudoers", "persistence", "post-exploitation"],
        related_alert_ids=["H006"],
    ),
    # H012 — NORMAL: Routine web traffic
    NetworkAlert(
        alert_id="H012",
        timestamp=_ts(2, 20, 30),
        source_ip="10.0.1.35",
        dest_ip="104.244.42.65",
        source_port=52200,
        dest_port=443,
        protocol="TCP",
        bytes_transferred=48_640,
        packets_count=75,
        duration_seconds=4.1,
        alert_type_raw="HTTPS outbound — Twitter/X CDN",
        description=(
            "Workstation 10.0.1.35 HTTPS to Twitter CDN (104.244.42.65). "
            "47 KB download of media assets. Valid TLS, normal browser UA. "
            "Routine social media access during business hours. No anomalies."
        ),
        severity=SeverityLevel.INFO,
        frequency=1,
        geo_location="US",
        threat_score=0.1,
        tags=["https", "social-media", "benign"],
    ),
    # H013 — HIGH: Malware download
    NetworkAlert(
        alert_id="H013",
        timestamp=_ts(2, 21, 0),
        source_ip="10.0.1.55",
        dest_ip="5.188.206.14",
        source_port=51800,
        dest_port=80,
        protocol="TCP",
        bytes_transferred=2_621_440,
        packets_count=1_820,
        duration_seconds=22.0,
        alert_type_raw="Malware download — known exploit dropper site",
        description=(
            "Host 10.0.1.55 downloaded 2.5 MB from 5.188.206.14:80 (RU, known malware hosting). "
            "HTTP GET /update.exe. File hash matches Emotet dropper (VirusTotal: 54/72 detections). "
            "Destination IP on MalwareBazaar blocklist. Download completed successfully."
        ),
        severity=SeverityLevel.HIGH,
        frequency=1,
        geo_location="RU",
        threat_score=9.3,
        tags=["malware", "emotet", "dropper", "known-bad-ip", "antivirus-match"],
    ),
    # H014 — RED HERRING: Internal dev server (odd port, but legitimate)
    NetworkAlert(
        alert_id="H014",
        timestamp=_ts(2, 21, 30),
        source_ip="10.0.1.50",
        dest_ip="10.0.1.1",
        source_port=52500,
        dest_port=8080,
        protocol="TCP",
        bytes_transferred=15_360,
        packets_count=28,
        duration_seconds=1.9,
        alert_type_raw="Non-standard port access — internal",
        description=(
            "Internal host 10.0.1.50 connecting to 10.0.1.1:8080. "
            "10.0.1.1 runs a documented internal dev/staging API server on port 8080. "
            "Connection from engineering subnet, valid service account. "
            "CMDB records: 10.0.1.1:8080 = 'internal-api-dev' service, owner: engineering team."
        ),
        severity=SeverityLevel.LOW,
        frequency=1,
        geo_location="INTERNAL",
        threat_score=1.5,
        tags=["internal-traffic", "non-standard-port", "documented-service"],
    ),
    # H015 — HIGH: Web login brute force
    NetworkAlert(
        alert_id="H015",
        timestamp=_ts(2, 22, 0),
        source_ip="185.220.101.45",
        dest_ip="10.0.1.1",
        source_port=58900,
        dest_port=8080,
        protocol="TCP",
        bytes_transferred=102_400,
        packets_count=1_024,
        duration_seconds=120.0,
        alert_type_raw="HTTP login brute-force — web application",
        description=(
            "Tor exit node 185.220.101.45 (same as H003) making 1,024 POST requests to "
            "10.0.1.1:8080/api/auth/login in 2 minutes. "
            "Username field cycling through common admin names. "
            "WAF detected but not blocking (rate limit not configured for internal IPs)."
        ),
        severity=SeverityLevel.HIGH,
        frequency=1024,
        geo_location="DE",
        threat_score=8.4,
        tags=["brute-force", "web-login", "tor", "waf-bypass"],
        related_alert_ids=["H003"],
    ),
    # H016 — HIGH: DNS tunneling / data exfil via DNS
    NetworkAlert(
        alert_id="H016",
        timestamp=_ts(2, 22, 30),
        source_ip="10.0.1.40",
        dest_ip="8.8.8.8",
        source_port=53100,
        dest_port=53,
        protocol="UDP",
        bytes_transferred=153_600,
        packets_count=1_000,
        duration_seconds=180.0,
        alert_type_raw="DNS tunneling — high-entropy domain queries",
        description=(
            "Host 10.0.1.40 sending 150 KB via DNS to 8.8.8.8 over 3 minutes. "
            "Average query length 158 bytes (normal: 32 bytes). "
            "Queried domains: 6f73646e7362736e6462.evil-c2.biz, 61646d696e706173.evil-c2.biz (hex-encoded). "
            "Shannon entropy of subdomains: 4.8 (tunneling threshold: 3.5). Tool match: iodine/dnscat2."
        ),
        severity=SeverityLevel.HIGH,
        frequency=1000,
        geo_location="INTERNAL",
        threat_score=8.9,
        tags=["dns-tunneling", "data-exfiltration", "covert-channel", "high-entropy"],
    ),
    # H017 — NORMAL: Routine SMTP
    NetworkAlert(
        alert_id="H017",
        timestamp=_ts(2, 23, 0),
        source_ip="10.0.1.5",
        dest_ip="74.125.130.27",
        source_port=54300,
        dest_port=25,
        protocol="TCP",
        bytes_transferred=8_192,
        packets_count=18,
        duration_seconds=1.5,
        alert_type_raw="SMTP outbound — mail relay",
        description=(
            "Mail server 10.0.1.5 relaying outbound email to Google MX (74.125.130.27). "
            "SMTP AUTH with TLS. 1 message, 8 KB. DKIM/SPF pass. "
            "Consistent with normal corporate email flow."
        ),
        severity=SeverityLevel.INFO,
        frequency=1,
        geo_location="US",
        threat_score=0.2,
        tags=["smtp", "email", "benign"],
    ),
    # H018 — MEDIUM: Reconnaissance / HTTP fingerprinting
    NetworkAlert(
        alert_id="H018",
        timestamp=_ts(2, 23, 30),
        source_ip="198.235.24.200",
        dest_ip="10.0.1.1",
        source_port=55000,
        dest_port=80,
        protocol="TCP",
        bytes_transferred=4_096,
        packets_count=45,
        duration_seconds=6.5,
        alert_type_raw="HTTP fingerprinting — version detection",
        description=(
            "IP 198.235.24.200 sent HTTP requests crafted for server fingerprinting: "
            "OPTIONS *, TRACE /, invalid methods. User-Agent: 'Nuclei/2.9.5 (ProjectDiscovery)'. "
            "Probing for Apache/Nginx version banners. Moderate threat — automated scanner."
        ),
        severity=SeverityLevel.MEDIUM,
        frequency=1,
        geo_location="US",
        threat_score=5.5,
        tags=["reconnaissance", "http-fingerprinting", "nuclei-scanner"],
    ),
    # H019 — RED HERRING: Scheduled rsync backup
    NetworkAlert(
        alert_id="H019",
        timestamp=_ts(2, 0, 5),
        source_ip="10.0.1.100",
        dest_ip="10.0.1.200",
        source_port=52000,
        dest_port=873,
        protocol="TCP",
        bytes_transferred=10_737_418_240,
        packets_count=7_340_032,
        duration_seconds=3_600.0,
        alert_type_raw="Large internal rsync transfer",
        description=(
            "Backup host 10.0.1.100 rsync'd 10 GB to NAS 10.0.1.200 via port 873 starting at 02:00. "
            "Matches documented nightly backup schedule (cron: 0 2 * * * rsync). "
            "Both hosts in 'infrastructure' VLAN. Transfer completed normally. "
            "CMDB: 10.0.1.200 = primary NAS, backup window 02:00–06:00."
        ),
        severity=SeverityLevel.INFO,
        frequency=1,
        geo_location="INTERNAL",
        threat_score=0.5,
        tags=["rsync", "backup", "scheduled", "internal", "benign"],
    ),
    # H020 — CRITICAL: Lateral movement via RDP from exfil host
    NetworkAlert(
        alert_id="H020",
        timestamp=_ts(2, 24, 0),
        source_ip="10.0.1.22",
        dest_ip="10.0.1.60",
        source_port=49700,
        dest_port=3389,
        protocol="TCP",
        bytes_transferred=512_000,
        packets_count=2_100,
        duration_seconds=45.0,
        alert_type_raw="RDP lateral movement from known-exfil host",
        description=(
            "Host 10.0.1.22 (data-exfil H006, priv-esc H011) initiated RDP session to "
            "10.0.1.60 (executive workstation). 500 KB transferred — consistent with screen rendering. "
            "RDP from this source IP is not authorized per access control policy. "
            "Third lateral movement from 10.0.1.22 in this incident."
        ),
        severity=SeverityLevel.CRITICAL,
        frequency=1,
        geo_location="INTERNAL",
        threat_score=10.0,
        tags=["lateral-movement", "rdp", "executive-target", "post-exploitation"],
        related_alert_ids=["H006", "H011"],
    ),
]

# Correct priority ordering (CRITICAL first, then HIGH, MEDIUM, LOW/normal)
HARD_PRIORITY_ORDER: list[str] = [
    # CRITICAL (handle first)
    "H001", "H006", "H007", "H011", "H020",
    # HIGH
    "H003", "H004", "H009", "H013", "H015", "H016",
    # MEDIUM
    "H010", "H018",
    # LOW / normal (last)
    "H002", "H005", "H008", "H012", "H014", "H017", "H019",
]

HARD_CRITICAL_IDS: set[str] = {"H001", "H006", "H007", "H011", "H020"}
HARD_HIGH_IDS: set[str] = {"H003", "H004", "H009", "H013", "H015", "H016"}

HARD_GROUND_TRUTH: dict = {
    "classifications": {
        "H001": "malware",
        "H002": "normal",
        "H003": "brute_force",
        "H004": "port_scan",
        "H005": "normal",
        "H006": "data_exfiltration",
        "H007": "lateral_movement",
        "H008": "normal",
        "H009": "ddos",
        "H010": "reconnaissance",
        "H011": "privilege_escalation",
        "H012": "normal",
        "H013": "malware",
        "H014": "normal",
        "H015": "brute_force",
        "H016": "data_exfiltration",
        "H017": "normal",
        "H018": "reconnaissance",
        "H019": "normal",
        "H020": "lateral_movement",
    },
    "actions": {
        "H001": "block",
        "H002": "ignore",
        "H003": "block",
        "H004": "block",
        "H005": "ignore",
        "H006": "escalate",
        "H007": "block",
        "H008": "ignore",
        "H009": "escalate",
        "H010": "investigate",
        "H011": "escalate",
        "H012": "ignore",
        "H013": "block",
        "H014": "monitor",
        "H015": "rate_limit",
        "H016": "block",
        "H017": "ignore",
        "H018": "rate_limit",
        "H019": "ignore",
        "H020": "block",
    },
    "is_threat": {
        "H001": True,  "H002": False, "H003": True,  "H004": True,
        "H005": False, "H006": True,  "H007": True,  "H008": False,
        "H009": True,  "H010": True,  "H011": True,  "H012": False,
        "H013": True,  "H014": False, "H015": True,  "H016": True,
        "H017": False, "H018": True,  "H019": False, "H020": True,
    },
    "is_critical": {
        "H001": True,  "H002": False, "H003": False, "H004": False,
        "H005": False, "H006": True,  "H007": True,  "H008": False,
        "H009": False, "H010": False, "H011": True,  "H012": False,
        "H013": False, "H014": False, "H015": False, "H016": False,
        "H017": False, "H018": False, "H019": False, "H020": True,
    },
    "acceptable_actions": {
        "H001": {"block": 1.0, "escalate": 0.7, "investigate": 0.3, "monitor": 0.1, "rate_limit": 0.0, "ignore": -1.0},
        "H002": {"ignore": 1.0, "monitor": 0.5, "investigate": 0.2, "rate_limit": -0.2, "escalate": -0.3, "block": -1.5},
        "H003": {"block": 1.0, "escalate": 0.7, "rate_limit": 0.4, "investigate": 0.2, "monitor": 0.1, "ignore": -0.8},
        "H004": {"block": 1.0, "escalate": 0.6, "rate_limit": 0.3, "investigate": 0.2, "monitor": 0.1, "ignore": -0.8},
        "H005": {"ignore": 1.0, "monitor": 0.5, "investigate": 0.2, "rate_limit": -0.2, "escalate": -0.2, "block": -1.5},
        "H006": {"escalate": 1.0, "block": 0.5, "investigate": 0.4, "monitor": 0.1, "rate_limit": 0.0, "ignore": -1.0},
        "H007": {"block": 1.0, "escalate": 0.8, "investigate": 0.3, "monitor": 0.1, "rate_limit": 0.0, "ignore": -1.0},
        "H008": {"ignore": 1.0, "monitor": 0.5, "investigate": 0.2, "rate_limit": -0.2, "escalate": -0.2, "block": -1.5},
        "H009": {"escalate": 1.0, "block": 0.5, "rate_limit": 0.3, "investigate": 0.2, "monitor": 0.1, "ignore": -0.8},
        "H010": {"investigate": 1.0, "monitor": 0.6, "escalate": 0.5, "rate_limit": 0.2, "ignore": -0.3, "block": -0.8},
        "H011": {"escalate": 1.0, "block": 0.6, "investigate": 0.3, "monitor": 0.1, "rate_limit": 0.0, "ignore": -1.0},
        "H012": {"ignore": 1.0, "monitor": 0.5, "investigate": 0.2, "rate_limit": -0.2, "escalate": -0.2, "block": -1.5},
        "H013": {"block": 1.0, "escalate": 0.7, "investigate": 0.3, "monitor": 0.1, "rate_limit": 0.0, "ignore": -0.8},
        "H014": {"monitor": 1.0, "ignore": 0.6, "investigate": 0.5, "rate_limit": 0.1, "escalate": -0.1, "block": -1.5},
        "H015": {"rate_limit": 1.0, "block": 0.8, "escalate": 0.5, "investigate": 0.3, "monitor": 0.1, "ignore": -0.8},
        "H016": {"block": 1.0, "escalate": 0.7, "investigate": 0.4, "rate_limit": 0.2, "monitor": 0.1, "ignore": -0.8},
        "H017": {"ignore": 1.0, "monitor": 0.5, "investigate": 0.2, "rate_limit": -0.2, "escalate": -0.2, "block": -1.5},
        "H018": {"rate_limit": 1.0, "block": 0.6, "investigate": 0.5, "monitor": 0.4, "escalate": 0.3, "ignore": -0.4},
        "H019": {"ignore": 1.0, "monitor": 0.5, "investigate": 0.2, "rate_limit": -0.2, "escalate": -0.2, "block": -1.5},
        "H020": {"block": 1.0, "escalate": 0.8, "investigate": 0.3, "monitor": 0.1, "rate_limit": 0.0, "ignore": -1.0},
    },
    "acceptable_classifications": {
        "H001": {"malware": 1.0, "reconnaissance": 0.3, "unknown": 0.2},
        "H002": {"normal": 1.0, "data_exfiltration": -0.2},
        "H003": {"brute_force": 1.0, "reconnaissance": 0.3},
        "H004": {"port_scan": 1.0, "reconnaissance": 0.7},
        "H005": {"normal": 1.0},
        "H006": {"data_exfiltration": 1.0, "malware": 0.4, "unknown": 0.2},
        "H007": {"lateral_movement": 1.0, "malware": 0.5, "reconnaissance": 0.2},
        "H008": {"normal": 1.0},
        "H009": {"ddos": 1.0, "reconnaissance": 0.2},
        "H010": {"reconnaissance": 1.0, "port_scan": 0.6, "unknown": 0.3},
        "H011": {"privilege_escalation": 1.0, "lateral_movement": 0.5, "malware": 0.3},
        "H012": {"normal": 1.0},
        "H013": {"malware": 1.0, "unknown": 0.2},
        "H014": {"normal": 1.0, "reconnaissance": 0.2},
        "H015": {"brute_force": 1.0, "reconnaissance": 0.3},
        "H016": {"data_exfiltration": 1.0, "malware": 0.4, "reconnaissance": 0.2},
        "H017": {"normal": 1.0},
        "H018": {"reconnaissance": 1.0, "port_scan": 0.3},
        "H019": {"normal": 1.0, "data_exfiltration": -0.3},
        "H020": {"lateral_movement": 1.0, "malware": 0.4},
    },
    "priority_order": HARD_PRIORITY_ORDER,
    "critical_ids": list(HARD_CRITICAL_IDS),
    "high_ids": list(HARD_HIGH_IDS),
}
