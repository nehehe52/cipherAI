"""
PCAP / PCAPNG Network Packet Capture Parser & Flow Reconstructor.
Extracts 5-tuple encrypted flows, TLS ClientHello records, and SNI domain metadata,
then feeds them to the AI detection engine. Also includes a synthetic PCAP generator.
"""

import time
import os
import struct
from collections import defaultdict
from typing import Dict, List, Any, Optional, Tuple
from scapy.utils import rdpcap, wrpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from core.tls_fingerprint import calculate_ja3, analyze_sni


def parse_tls_client_hello(payload: bytes) -> Dict[str, Any]:
    """
    Parses raw TLS Record layer for ClientHello (Type 22, Handshake Type 1).
    Extracts TLS Version, Cipher Suites, Extensions, and SNI if present.
    """
    result = {
        "is_client_hello": False,
        "tls_version": None,
        "cipher_suites": [],
        "extensions": [],
        "sni": None
    }

    try:
        if len(payload) < 43:
            return result
        # Check TLS Record: ContentType 22 (Handshake), Version (0x0301 or 0x0303)
        if payload[0] != 22:
            return result

        record_len = struct.unpack("!H", payload[3:5])[0]
        handshake_payload = payload[5:5 + record_len]
        if len(handshake_payload) < 38 or handshake_payload[0] != 1:  # Handshake type 1 = ClientHello
            return result

        result["is_client_hello"] = True
        client_version = struct.unpack("!H", handshake_payload[4:6])[0]
        result["tls_version"] = client_version

        # Skip Random (32 bytes)
        pos = 6 + 32
        # Session ID length
        session_id_len = handshake_payload[pos]
        pos += 1 + session_id_len

        # Cipher Suites
        cipher_suites_len = struct.unpack("!H", handshake_payload[pos:pos+2])[0]
        pos += 2
        cipher_suites = []
        for i in range(0, cipher_suites_len, 2):
            cs = struct.unpack("!H", handshake_payload[pos + i:pos + i + 2])[0]
            cipher_suites.append(cs)
        result["cipher_suites"] = cipher_suites
        pos += cipher_suites_len

        # Compression Methods
        comp_methods_len = handshake_payload[pos]
        pos += 1 + comp_methods_len

        # Extensions
        if pos + 2 <= len(handshake_payload):
            exts_len = struct.unpack("!H", handshake_payload[pos:pos+2])[0]
            pos += 2
            ext_end = pos + exts_len
            extensions = []
            while pos + 4 <= ext_end and pos + 4 <= len(handshake_payload):
                ext_type = struct.unpack("!H", handshake_payload[pos:pos+2])[0]
                ext_len = struct.unpack("!H", handshake_payload[pos+2:pos+4])[0]
                extensions.append(ext_type)
                pos += 4

                # Check for SNI extension (Type 0x0000)
                if ext_type == 0 and pos + ext_len <= len(handshake_payload):
                    sni_data = handshake_payload[pos:pos + ext_len]
                    if len(sni_data) > 5:
                        # Server name list length (2 bytes), type (1 byte = 0), length (2 bytes)
                        name_len = struct.unpack("!H", sni_data[3:5])[0]
                        name = sni_data[5:5 + name_len].decode("utf-8", errors="ignore")
                        result["sni"] = name

                pos += ext_len
            result["extensions"] = extensions

    except Exception:
        pass

    return result


class PCAPAnalyzer:
    """Reads PCAP files and extracts reconstructed encrypted network flows."""

    def __init__(self):
        pass

    def analyze_pcap_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Parses a PCAP file and aggregates packets into 5-tuple flow objects."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"PCAP file not found: {filepath}")

        packets = rdpcap(filepath)
        raw_flows = defaultdict(lambda: {
            "packet_lengths": [],
            "packet_directions": [],
            "packet_timestamps": [],
            "sni": None,
            "tls_info": None,
            "proto": "TCP/TLS"
        })

        for pkt in packets:
            if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                continue

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            pkt_time = float(pkt.time)
            pkt_len = len(pkt)

            # Standardize 5-tuple key: canonical order
            if (src_ip, src_port) < (dst_ip, dst_port):
                flow_key = (src_ip, src_port, dst_ip, dst_port)
                direction = 1  # Forward
            else:
                flow_key = (dst_ip, dst_port, src_ip, src_port)
                direction = -1  # Backward

            flow_entry = raw_flows[flow_key]
            flow_entry["packet_lengths"].append(pkt_len)
            flow_entry["packet_directions"].append(direction)
            flow_entry["packet_timestamps"].append(pkt_time)

            # Check if payload contains TLS ClientHello
            if pkt.haslayer(Raw) and not flow_entry["sni"]:
                tls_info = parse_tls_client_hello(bytes(pkt[Raw]))
                if tls_info["is_client_hello"]:
                    flow_entry["tls_info"] = tls_info
                    if tls_info["sni"]:
                        flow_entry["sni"] = tls_info["sni"]

        # Convert raw grouped flows into standardized flow dictionaries
        reconstructed_flows = []
        flow_idx = 1
        for (f_src_ip, f_src_port, f_dst_ip, f_dst_port), data in raw_flows.items():
            sni = data["sni"] or f"encrypted-host-{f_dst_ip}"
            sni_meta = analyze_sni(sni)
            
            # Estimate JA3 or calculate if TLS metadata exists
            tls_meta = data["tls_info"]
            if tls_meta and tls_meta.get("is_client_hello"):
                _, ja3_hash = calculate_ja3(
                    tls_version=tls_meta["tls_version"] or 771,
                    cipher_suites=tls_meta["cipher_suites"],
                    extensions=tls_meta["extensions"],
                    elliptic_curves=[29, 23, 24],
                    ec_point_formats=[0]
                )
            else:
                ja3_hash = "cd08e31494f9531f560d64cfa3f2233c"  # Standard default

            timestamps = data["packet_timestamps"]
            duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.05
            
            flow_dict = {
                "flow_id": f"PCAP-FLW-{flow_idx:04d}",
                "timestamp": timestamps[0] if timestamps else time.time(),
                "src_ip": f_src_ip,
                "src_port": f_src_port,
                "dst_ip": f_dst_ip,
                "dst_port": f_dst_port,
                "proto": "TLS 1.2/1.3",
                "sni": sni,
                "sni_entropy": sni_meta["entropy"],
                "ja3_hash": ja3_hash,
                "ja3_threat": False,
                "packet_lengths": data["packet_lengths"],
                "packet_directions": data["packet_directions"],
                "packet_timestamps": timestamps,
                "duration": duration,
                "total_packets": len(data["packet_lengths"]),
                "total_bytes": sum(data["packet_lengths"])
            }
            reconstructed_flows.append(flow_dict)
            flow_idx += 1

        return reconstructed_flows


def generate_sample_pcap(output_filepath: str):
    """
    Generates a realistic synthetic PCAP file with:
    1. Normal Web browsing HTTPS flow
    2. Cobalt Strike C2 Beaconing flow (low jitter periodic heartbeats)
    3. Encrypted Data Exfiltration burst flow
    """
    packets = []
    base_time = time.time() - 120.0

    # 1. Normal HTTPS flow
    client_ip = "192.168.1.105"
    server_ip = "140.82.121.4"  # GitHub
    sport = 52344
    dport = 443

    # Simulated ClientHello packet with dummy TLS payload
    tls_payload = b"\x16\x03\x01\x00\x60\x01\x00\x00\x5c\x03\x03" + (b"\xaa" * 32) + b"\x00\x00\x04\xc0\x2f\xc0\x30\x01\x00"
    p1 = IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=dport, flags="PA") / Raw(load=tls_payload)
    p1.time = base_time
    packets.append(p1)

    for i in range(1, 20):
        t = base_time + i * 0.4
        if i % 3 == 0:
            pkt = IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=dport) / Raw(load=b"\x00" * 150)
        else:
            pkt = IP(src=server_ip, dst=client_ip) / TCP(sport=dport, dport=sport) / Raw(load=b"\x00" * 1350)
        pkt.time = t
        packets.append(pkt)

    # 2. Cobalt Strike C2 Beacon Flow (low jitter 5s heartbeat to suspicious IP)
    c2_ip = "185.220.101.5"
    c2_sport = 49812
    for pulse in range(6):
        t_pulse = base_time + 10.0 + (pulse * 5.0) + (0.02 * (pulse % 2))
        p_req = IP(src=client_ip, dst=c2_ip) / TCP(sport=c2_sport, dport=443) / Raw(load=b"\x00" * 280)
        p_req.time = t_pulse
        packets.append(p_req)

        p_res = IP(src=c2_ip, dst=client_ip) / TCP(sport=443, dport=c2_sport) / Raw(load=b"\x00" * 160)
        p_res.time = t_pulse + 0.05
        packets.append(p_res)

    # 3. Data Exfiltration flow (heavy upload to remote VPS)
    exfil_ip = "45.154.255.8"
    exfil_sport = 55100
    for ex in range(40):
        t_ex = base_time + 50.0 + (ex * 0.08)
        p_data = IP(src=client_ip, dst=exfil_ip) / TCP(sport=exfil_sport, dport=443) / Raw(load=b"\x00" * 1420)
        p_data.time = t_ex
        packets.append(p_data)

    # Sort all packets by timestamp
    packets.sort(key=lambda p: float(p.time))
    wrpcap(output_filepath, packets)
    return output_filepath
