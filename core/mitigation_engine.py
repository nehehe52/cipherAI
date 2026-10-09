"""
Automated Mitigation Engine and SOAR Response Generator.
Provides MITRE ATT&CK mapping, severity classification, dynamic firewall rule generation
(Windows Firewall / iptables), and live IP quarantine management.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any

# MITRE ATT&CK Mapping for Encrypted Network Traffic Threats
MITRE_MAPPING = {
    "C2_BEACONING": {
        "tactic": "Command and Control",
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols (TLS/HTTPS)",
        "sub_technique": "T1573.002 - Encrypted Channel: Asymmetric Cryptography",
        "severity": "CRITICAL",
        "recommended_action": "Isolate host, terminate TLS session, block destination C2 IP at perimeter firewall."
    },
    "DATA_EXFILTRATION": {
        "tactic": "Exfiltration",
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel / Web Service",
        "sub_technique": "T1567.002 - Exfiltration to Cloud Storage",
        "severity": "CRITICAL",
        "recommended_action": "Block outbound socket, revoke compromised credentials, conduct forensic snapshot of source endpoint."
    },
    "TOR_PROXY_TUNNEL": {
        "tactic": "Command and Control / Defense Evasion",
        "technique_id": "T1090.003",
        "technique_name": "Proxy: Multi-hop Proxy (Tor / Onion Routing)",
        "sub_technique": "T1572 - Protocol Tunneling over Port 443",
        "severity": "HIGH",
        "recommended_action": "Apply egress policy drop, inspect client host for unauthorized Tor client / proxy daemon."
    },
    "DOH_DATA_TUNNEL": {
        "tactic": "Command and Control / Exfiltration",
        "technique_id": "T1071.004",
        "technique_name": "Application Layer Protocol: DNS over HTTPS",
        "sub_technique": "T1568.002 - Domain Generation Algorithms (DGA)",
        "severity": "HIGH",
        "recommended_action": "Enforce corporate DoH gateway, block direct public DoH resolvers (Cloudflare/Google) on endpoint."
    },
    "TLS_DDOS_FLOOD": {
        "tactic": "Impact",
        "technique_id": "T1498.001",
        "technique_name": "Network Denial of Service: Direct Network Flood",
        "sub_technique": "T1499.002 - Endpoint Denial of Service: SSL Handshake Exhaustion",
        "severity": "MEDIUM",
        "recommended_action": "Enable SYN/SSL rate limiting on reverse proxy / WAF, apply dynamic connection throttling."
    },
    "BENIGN_WEB": {
        "tactic": "None",
        "technique_id": "N/A",
        "technique_name": "Legitimate Encrypted Traffic",
        "sub_technique": "N/A",
        "severity": "BENIGN",
        "recommended_action": "Allow traffic without intervention."
    },
    "BENIGN_STREAMING": {
        "tactic": "None",
        "technique_id": "N/A",
        "technique_name": "High-Bandwidth Encrypted Media Stream",
        "sub_technique": "N/A",
        "severity": "BENIGN",
        "recommended_action": "Allow traffic without intervention."
    },
    "ANOMALOUS_UNKNOWN": {
        "tactic": "Initial Access / Suspicious Encrypted Flow",
        "technique_id": "T1205",
        "technique_name": "Traffic Signaling / Outlier Encrypted Session",
        "sub_technique": "N/A",
        "severity": "HIGH",
        "recommended_action": "Quarantine session and inspect with Deep Packet Inspection / Sandbox."
    }
}


class MitigationEngine:
    """Manages active mitigations, quarantine states, and firewall scripts."""

    def __init__(self):
        # In-memory quarantine list: {ip: {timestamp, threat, reason, firewall_rule}}
        self.quarantined_ips: Dict[str, Dict[str, Any]] = {}
        self.incident_history: List[Dict[str, Any]] = []

    def get_mitre_info(self, threat_type: str) -> Dict[str, str]:
        """Returns MITRE ATT&CK details for a detected threat."""
        return MITRE_MAPPING.get(threat_type, MITRE_MAPPING["ANOMALOUS_UNKNOWN"])

    def generate_firewall_commands(self, src_ip: str, dst_ip: str, dst_port: int, threat_type: str) -> Dict[str, str]:
        """
        Generates production-grade OS firewall commands for rapid isolation.
        """
        rule_name = f"AG_BLOCK_{threat_type}_{dst_ip}".replace(".", "_").replace(" ", "_")
        
        # Windows Firewall command (netsh)
        win_cmd = (
            f'netsh advfirewall firewall add rule name="{rule_name}" '
            f'dir=out action=block remoteip={dst_ip} protocol=TCP remoteport={dst_port}'
        )
        
        # Linux iptables command
        linux_cmd = f"iptables -I OUTPUT -d {dst_ip} -p tcp --dport {dst_port} -j DROP"

        # PowerShell NetSecurity command
        ps_cmd = (
            f'New-NetFirewallRule -DisplayName "{rule_name}" -Direction Outbound '
            f'-Action Block -RemoteAddress {dst_ip} -RemotePort {dst_port} -Protocol TCP'
        )

        return {
            "rule_name": rule_name,
            "windows_netsh": win_cmd,
            "windows_powershell": ps_cmd,
            "linux_iptables": linux_cmd
        }

    def quarantine_ip(self, ip: str, threat_type: str, anomaly_score: float, details: str) -> Dict[str, Any]:
        """Adds an IP to the quarantine registry and generates automated isolation instructions."""
        mitre = self.get_mitre_info(threat_type)
        fw = self.generate_firewall_commands(src_ip="192.168.1.100", dst_ip=ip, dst_port=443, threat_type=threat_type)
        
        entry = {
            "ip": ip,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "threat_type": threat_type,
            "severity": mitre["severity"],
            "anomaly_score": anomaly_score,
            "details": details,
            "firewall_rules": fw,
            "status": "ACTIVE_BLOCKED"
        }
        self.quarantined_ips[ip] = entry
        return entry

    def release_ip(self, ip: str) -> bool:
        """Releases an IP from quarantine."""
        if ip in self.quarantined_ips:
            del self.quarantined_ips[ip]
            return True
        return False

    def is_quarantined(self, ip: str) -> bool:
        """Checks if IP is currently quarantined."""
        return ip in self.quarantined_ips

    def create_incident_ticket(self, flow: Dict[str, Any], threat_type: str, anomaly_score: float, xai_reason: str) -> Dict[str, Any]:
        """Creates a standardized SOC Incident Ticket."""
        mitre = self.get_mitre_info(threat_type)
        ticket_id = f"INC-{int(datetime.now().timestamp())}-{len(self.incident_history) + 1}"
        
        ticket = {
            "incident_id": ticket_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "threat_type": threat_type,
            "severity": mitre["severity"],
            "anomaly_score": round(anomaly_score, 3),
            "source_endpoint": f"{flow.get('src_ip', '192.168.1.45')}:{flow.get('src_port', 51234)}",
            "destination_target": f"{flow.get('dst_ip', '104.244.42.1')}:{flow.get('dst_port', 443)}",
            "sni_domain": flow.get("sni", "Unknown"),
            "ja3_hash": flow.get("ja3_hash", "N/A"),
            "mitre_tactic": mitre["tactic"],
            "mitre_technique": f"{mitre['technique_id']} - {mitre['technique_name']}",
            "ai_explanation": xai_reason,
            "recommended_action": mitre["recommended_action"],
            "firewall_commands": self.generate_firewall_commands(
                flow.get("src_ip", "192.168.1.45"),
                flow.get("dst_ip", "104.244.42.1"),
                flow.get("dst_port", 443),
                threat_type
            )
        }
        self.incident_history.append(ticket)
        return ticket
