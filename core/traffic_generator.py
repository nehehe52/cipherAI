"""
Encrypted Network Traffic Stream Simulator & Threat Injector.
Generates realistic TLS 1.2/1.3 flows (benign web, media streaming, API calls)
and provides on-demand injection of encrypted cyber threats (Cobalt Strike C2, Exfiltration, Tor, DoH).
"""

import time
import random
from typing import Dict, List, Any, Optional

BENIGN_DOMAINS = [
    ("api.github.com", "140.82.121.4", "cd08e31494f9531f560d64cfa3f2233c"),
    ("www.google.com", "172.217.16.206", "cd08e31494f9531f560d64cfa3f2233c"),
    ("teams.microsoft.com", "52.114.159.20", "cd08e31494f9531f560d64cfa3f2233c"),
    ("video.netflix.com", "198.38.118.150", "b38455a272046096e6a1aa94ec4392e2"),
    ("cdn.cloudflare.net", "104.16.132.229", "999654497e6515b8004f1fb93e2dd60a"),
    ("gateway.aws.amazon.com", "54.239.28.85", "771fedcc35de56d9269e437457141663"),
    ("en.wikipedia.org", "91.198.174.192", "b38455a272046096e6a1aa94ec4392e2"),
    ("internal-auth.corp.local", "10.0.4.15", "cd08e31494f9531f560d64cfa3f2233c")
]

INTERNAL_IPS = [
    "192.168.1.105", "192.168.1.112", "192.168.1.144",
    "192.168.1.189", "192.168.1.201", "192.168.1.233"
]


class EncryptedTrafficGenerator:
    """Generates realistic encrypted flows with optional malicious threat injection."""

    def __init__(self):
        self.flow_counter = 0

    def _next_flow_id(self) -> str:
        self.flow_counter += 1
        return f"FLW-{int(time.time()) % 100000:05d}-{self.flow_counter}"

    def generate_benign_flow(self, flow_type: str = "web") -> Dict[str, Any]:
        """Generates clean, normal HTTPS/TLS traffic."""
        domain, dst_ip, ja3 = random.choice(BENIGN_DOMAINS)
        src_ip = random.choice(INTERNAL_IPS)
        src_port = random.randint(49152, 65535)
        now = time.time()

        if flow_type == "streaming" or "video" in domain:
            # Video / audio high-bandwidth stream
            num_packets = random.randint(120, 400)
            duration = random.uniform(8.0, 30.0)
            timestamps = sorted([now - random.uniform(0.1, duration) for _ in range(num_packets)])
            
            # 85% backward packets (server to client) with large payload
            directions = []
            lengths = []
            for _ in range(num_packets):
                if random.random() < 0.15:
                    directions.append(1)
                    lengths.append(random.choice([66, 120, 240]))
                else:
                    directions.append(-1)
                    lengths.append(random.randint(1100, 1460))

            sni_entropy = 2.45
            threat_hint = "BENIGN_STREAMING"
        else:
            # Normal Web / API browsing
            num_packets = random.randint(15, 60)
            duration = random.uniform(1.5, 12.0)
            timestamps = sorted([now - random.uniform(0.1, duration) for _ in range(num_packets)])
            
            directions = []
            lengths = []
            for _ in range(num_packets):
                if random.random() < 0.35:
                    directions.append(1)
                    lengths.append(random.randint(80, 500))
                else:
                    directions.append(-1)
                    lengths.append(random.randint(400, 1460))

            sni_entropy = 2.85
            threat_hint = "BENIGN_WEB"

        return {
            "flow_id": self._next_flow_id(),
            "timestamp": now,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": 443,
            "proto": "TLS 1.3",
            "sni": domain,
            "sni_entropy": sni_entropy,
            "ja3_hash": ja3,
            "ja3_threat": False,
            "packet_lengths": lengths,
            "packet_directions": directions,
            "packet_timestamps": timestamps,
            "duration": duration,
            "total_packets": len(lengths),
            "total_bytes": sum(lengths),
            "threat_label_truth": threat_hint
        }

    def generate_c2_beacon(self) -> Dict[str, Any]:
        """Injects a periodic Command & Control HTTPS beacon (e.g. Cobalt Strike / Sliver)."""
        src_ip = random.choice(INTERNAL_IPS)
        dst_ip = f"185.{random.randint(100, 250)}.{random.randint(10, 200)}.{random.randint(1, 250)}"
        domain = f"cdn-update-{random.randint(10, 99)}.top"
        ja3 = "a0e9f5d64349fb13191bc781f81f42e1"  # Cobalt Strike JA3
        
        now = time.time()
        # Characteristic: highly periodic IAT (e.g., 5.0 seconds interval with tiny jitter < 0.05s)
        base_interval = random.choice([3.0, 5.0, 10.0])
        num_pulses = random.randint(6, 12)
        timestamps = []
        lengths = []
        directions = []

        curr_t = now - (num_pulses * base_interval)
        for _ in range(num_pulses):
            jitter = random.uniform(-0.04, 0.04) * base_interval
            t = curr_t + jitter
            # Fwd check-in
            timestamps.append(t)
            directions.append(1)
            lengths.append(random.randint(240, 360))
            # Bwd response (NOP or small task)
            timestamps.append(t + random.uniform(0.02, 0.08))
            directions.append(-1)
            lengths.append(random.randint(120, 280))
            curr_t += base_interval

        return {
            "flow_id": self._next_flow_id(),
            "timestamp": now,
            "src_ip": src_ip,
            "src_port": random.randint(49152, 65535),
            "dst_ip": dst_ip,
            "dst_port": random.choice([443, 8443]),
            "proto": "TLS 1.2",
            "sni": domain,
            "sni_entropy": 3.82,
            "ja3_hash": ja3,
            "ja3_threat": True,
            "packet_lengths": lengths,
            "packet_directions": directions,
            "packet_timestamps": timestamps,
            "duration": max(timestamps) - min(timestamps),
            "total_packets": len(lengths),
            "total_bytes": sum(lengths),
            "threat_label_truth": "C2_BEACONING"
        }

    def generate_exfiltration(self) -> Dict[str, Any]:
        """Injects stealth encrypted data exfiltration (massive upload burst over TLS)."""
        src_ip = random.choice(INTERNAL_IPS)
        dst_ip = f"45.{random.randint(33, 199)}.{random.randint(1, 200)}.{random.randint(1, 250)}"
        domain = f"s3-sync-vault-{random.randint(100, 999)}.s3.amazonaws.com"
        ja3 = "51c64c77e60f3980eea90869b68c58a8"  # TrickBot / Exfil JA3
        
        now = time.time()
        num_packets = random.randint(180, 500)
        duration = random.uniform(4.0, 18.0)
        timestamps = sorted([now - random.uniform(0.1, duration) for _ in range(num_packets)])

        directions = []
        lengths = []
        # 88% forward packets with large MTU payloads (1380 - 1460 bytes)
        for _ in range(num_packets):
            if random.random() < 0.88:
                directions.append(1)
                lengths.append(random.randint(1380, 1460))
            else:
                directions.append(-1)
                lengths.append(random.choice([66, 78, 120]))

        return {
            "flow_id": self._next_flow_id(),
            "timestamp": now,
            "src_ip": src_ip,
            "src_port": random.randint(49152, 65535),
            "dst_ip": dst_ip,
            "dst_port": 443,
            "proto": "TLS 1.3",
            "sni": domain,
            "sni_entropy": 3.45,
            "ja3_hash": ja3,
            "ja3_threat": True,
            "packet_lengths": lengths,
            "packet_directions": directions,
            "packet_timestamps": timestamps,
            "duration": duration,
            "total_packets": len(lengths),
            "total_bytes": sum(lengths),
            "threat_label_truth": "DATA_EXFILTRATION"
        }

    def generate_tor_tunnel(self) -> Dict[str, Any]:
        """Injects Tor onion proxy circuit or encrypted tunnel session."""
        src_ip = random.choice(INTERNAL_IPS)
        dst_ip = f"194.26.{random.randint(10, 150)}.{random.randint(1, 250)}"
        ja3 = "406c117e6992d95188f1ae6a8ff4a0a5"  # Tor Browser JA3
        
        now = time.time()
        num_packets = random.randint(60, 180)
        duration = random.uniform(10.0, 45.0)
        timestamps = sorted([now - random.uniform(0.1, duration) for _ in range(num_packets)])

        # Fixed cell chunks (multiples of 512 bytes)
        directions = []
        lengths = []
        for _ in range(num_packets):
            dir_choice = 1 if random.random() < 0.52 else -1
            directions.append(dir_choice)
            lengths.append(random.choice([512, 544, 1024, 1088, 1460]))

        return {
            "flow_id": self._next_flow_id(),
            "timestamp": now,
            "src_ip": src_ip,
            "src_port": random.randint(49152, 65535),
            "dst_ip": dst_ip,
            "dst_port": random.choice([443, 9001]),
            "proto": "TLS 1.3 (Obfuscated)",
            "sni": "",  # Tor bridges often don't provide SNI
            "sni_entropy": 0.0,
            "ja3_hash": ja3,
            "ja3_threat": True,
            "packet_lengths": lengths,
            "packet_directions": directions,
            "packet_timestamps": timestamps,
            "duration": duration,
            "total_packets": len(lengths),
            "total_bytes": sum(lengths),
            "threat_label_truth": "TOR_PROXY_TUNNEL"
        }

    def generate_doh_tunnel(self) -> Dict[str, Any]:
        """Injects DNS-over-HTTPS covert data exfiltration tunnel."""
        src_ip = random.choice(INTERNAL_IPS)
        dst_ip = "1.1.1.1"  # Cloudflare DoH resolver or rogue resolver
        # Random long base32/hex subdomain
        encoded_data = "".join(random.choices("abcdef0123456789", k=28))
        domain = f"{encoded_data}.exfil-tunnel.xyz"
        ja3 = "771fedcc35de56d9269e437457141663"

        now = time.time()
        num_packets = random.randint(40, 100)
        duration = random.uniform(8.0, 30.0)
        timestamps = sorted([now - random.uniform(0.1, duration) for _ in range(num_packets)])

        directions = []
        lengths = []
        for _ in range(num_packets):
            if random.random() < 0.5:
                directions.append(1)
                lengths.append(random.randint(220, 380))
            else:
                directions.append(-1)
                lengths.append(random.randint(180, 320))

        return {
            "flow_id": self._next_flow_id(),
            "timestamp": now,
            "src_ip": src_ip,
            "src_port": random.randint(49152, 65535),
            "dst_ip": dst_ip,
            "dst_port": 443,
            "proto": "DoH (TLS 1.3)",
            "sni": domain,
            "sni_entropy": 4.15,
            "ja3_hash": ja3,
            "ja3_threat": False,
            "packet_lengths": lengths,
            "packet_directions": directions,
            "packet_timestamps": timestamps,
            "duration": duration,
            "total_packets": len(lengths),
            "total_bytes": sum(lengths),
            "threat_label_truth": "DOH_DATA_TUNNEL"
        }

    def generate_tls_flood(self) -> Dict[str, Any]:
        """Injects TLS handshake flood / SSL exhaustion attack."""
        src_ip = f"198.51.100.{random.randint(1, 254)}"
        dst_ip = "192.168.1.10"  # Target internal web service
        domain = "target.internal.corp"
        
        now = time.time()
        num_packets = random.randint(350, 1200)
        duration = random.uniform(0.5, 2.5)  # Extreme rate!
        timestamps = sorted([now - random.uniform(0.01, duration) for _ in range(num_packets)])

        directions = [1] * num_packets  # All outbound forward SYN/ClientHello floods
        lengths = [random.randint(66, 180) for _ in range(num_packets)]

        return {
            "flow_id": self._next_flow_id(),
            "timestamp": now,
            "src_ip": src_ip,
            "src_port": random.randint(1024, 65535),
            "dst_ip": dst_ip,
            "dst_port": 443,
            "proto": "TLS (Incomplete Flood)",
            "sni": domain,
            "sni_entropy": 2.65,
            "ja3_hash": "e7d705a3286e19ea42f587b344ee6865",
            "ja3_threat": True,
            "packet_lengths": lengths,
            "packet_directions": directions,
            "packet_timestamps": timestamps,
            "duration": duration,
            "total_packets": len(lengths),
            "total_bytes": sum(lengths),
            "threat_label_truth": "TLS_DDOS_FLOOD"
        }
