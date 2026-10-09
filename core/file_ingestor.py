"""
Unified Network Telemetry & File Ingestion Engine.
Supports multiple file formats beyond PCAP:
- CSV (Flow Telemetry, Wireshark Packet Export, Zeek conn.log CSV, CIC-IDS)
- JSON / JSONL (Flow lists, Suricata EVE JSON, Zeek JSON)
- Zeek TSV / LOG (conn.log, ssl.log)
- PCAP / PCAPNG / CAP (Raw packet capture files)
"""

import os
import json
import time
import pandas as pd
import numpy as np
from typing import Dict, List, Any, Optional

from core.pcap_analyzer import PCAPAnalyzer
from core.tls_fingerprint import analyze_sni, lookup_ja3
from core.feature_extractor import extract_flow_features, FEATURE_NAMES


class UniversalFileIngestor:
    """Universal multi-format parser for encrypted network traffic telemetry."""

    def __init__(self):
        self.pcap_analyzer = PCAPAnalyzer()

    def ingest_file(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Ingests and standardizes any supported network traffic file into
        a list of normalized flow dictionaries ready for AI detection.
        Supported formats: .pcap, .pcapng, .cap, .csv, .json, .jsonl, .log, .txt, .parquet
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        ext = os.path.splitext(filepath)[1].lower()

        if ext in [".pcap", ".pcapng", ".cap"]:
            return self.pcap_analyzer.analyze_pcap_file(filepath)
        elif ext == ".csv":
            return self._parse_csv_file(filepath)
        elif ext in [".json", ".jsonl"]:
            return self._parse_json_file(filepath)
        elif ext in [".log", ".txt"]:
            return self._parse_zeek_log_file(filepath)
        elif ext == ".parquet":
            return self._parse_parquet_file(filepath)
        else:
            # Fallback: attempt CSV, then JSON
            try:
                return self._parse_csv_file(filepath)
            except Exception:
                return self._parse_json_file(filepath)

    def _parse_csv_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Parses CSV formats: Flow CSV, Wireshark CSV, or Zeek conn.log CSV."""
        df = pd.read_csv(filepath)
        cols_lower = [str(c).lower().strip() for c in df.columns]
        cols_map = {str(c).lower().strip(): c for c in df.columns}

        # Check if it's a Wireshark Packet CSV Export (has 'No.', 'Time', 'Source', 'Destination', 'Length')
        if any("source" in c for c in cols_lower) and any("length" in c for c in cols_lower) and any("time" in c for c in cols_lower):
            return self._parse_wireshark_csv(df)

        # Check if it's a Zeek conn.log CSV
        if any("id.orig_h" in c for c in cols_lower) or any("orig_bytes" in c for c in cols_lower):
            return self._parse_zeek_csv(df)

        # Standard Flow Telemetry CSV
        flows = []
        for idx, row in df.iterrows():
            flow_id = str(row.get(cols_map.get("flow_id", "flow_id"), f"CSV-FLW-{idx+1:04d}"))
            src_ip = str(row.get(cols_map.get("src_ip", "source"), f"192.168.1.{(idx % 150) + 10}"))
            dst_ip = str(row.get(cols_map.get("dst_ip", "destination"), f"104.244.42.{(idx % 200) + 1}"))
            src_port = int(row.get(cols_map.get("src_port", "sport"), 49152 + (idx % 10000)))
            dst_port = int(row.get(cols_map.get("dst_port", "dport"), 443))
            sni = str(row.get(cols_map.get("sni", "domain"), "encrypted-session.net"))
            proto = str(row.get(cols_map.get("proto", "protocol"), "TLS 1.3"))

            tot_pkts = int(row.get(cols_map.get("total_packets", "packets"), 30))
            tot_bytes = float(row.get(cols_map.get("total_bytes", "bytes"), 15000.0))
            duration = max(float(row.get(cols_map.get("flow_duration", "duration"), 5.0)), 0.01)
            pcr = float(row.get(cols_map.get("pcr", "pcr"), 0.0))
            ja3 = str(row.get(cols_map.get("ja3_hash", "ja3"), "cd08e31494f9531f560d64cfa3f2233c"))
            sni_entropy = float(row.get(cols_map.get("sni_entropy", "sni_entropy"), analyze_sni(sni)["entropy"]))

            # Synthesize packet sequences if not explicitly in CSV
            pkt_mean = max(tot_bytes / max(tot_pkts, 1), 60.0)
            fwd_pkts = int(tot_pkts * ((1 + pcr) / 2)) if abs(pcr) <= 1.0 else tot_pkts // 2
            bwd_pkts = tot_pkts - fwd_pkts
            directions = [1] * fwd_pkts + [-1] * bwd_pkts
            lengths = [int(pkt_mean)] * tot_pkts
            now = time.time()
            timestamps = [now + (i * (duration / max(tot_pkts, 1))) for i in range(tot_pkts)]

            flow_dict = {
                "flow_id": flow_id,
                "timestamp": now,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "proto": proto,
                "sni": sni,
                "sni_entropy": sni_entropy,
                "ja3_hash": ja3,
                "ja3_threat": bool(row.get(cols_map.get("ja3_threat_flag", "ja3_threat"), False)),
                "packet_lengths": lengths,
                "packet_directions": directions,
                "packet_timestamps": timestamps,
                "duration": duration,
                "total_packets": tot_pkts,
                "total_bytes": tot_bytes,
                "threat_label_truth": str(row.get(cols_map.get("label", "label"), "UNKNOWN"))
            }
            flows.append(flow_dict)

        return flows

    def _parse_wireshark_csv(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Reconstructs flows from Wireshark packet-level CSV export."""
        cols_map = {str(c).lower().strip(): c for c in df.columns}
        src_col = cols_map.get("source", "Source")
        dst_col = cols_map.get("destination", "Destination")
        len_col = cols_map.get("length", "Length")
        time_col = cols_map.get("time", "Time")
        info_col = cols_map.get("info", cols_map.get("protocol", None))

        grouped = {}
        for idx, row in df.iterrows():
            s = str(row[src_col])
            d = str(row[dst_col])
            l = int(row[len_col]) if pd.notnull(row[len_col]) else 66
            t = float(row[time_col]) if pd.notnull(row[time_col]) else idx * 0.05

            key = tuple(sorted([s, d]))
            if key not in grouped:
                grouped[key] = {
                    "src_ip": s, "dst_ip": d,
                    "packet_lengths": [], "packet_directions": [], "packet_timestamps": []
                }
            direction = 1 if s == grouped[key]["src_ip"] else -1
            grouped[key]["packet_lengths"].append(l)
            grouped[key]["packet_directions"].append(direction)
            grouped[key]["packet_timestamps"].append(t)

        flows = []
        flow_idx = 1
        for key, g in grouped.items():
            ts = g["packet_timestamps"]
            dur = max(ts[-1] - ts[0], 0.05) if len(ts) > 1 else 0.05
            flows.append({
                "flow_id": f"WSHARK-FLW-{flow_idx:04d}",
                "timestamp": ts[0],
                "src_ip": g["src_ip"],
                "src_port": 50000 + (flow_idx % 1000),
                "dst_ip": g["dst_ip"],
                "dst_port": 443,
                "proto": "TLS 1.3",
                "sni": f"host-{g['dst_ip']}.net",
                "sni_entropy": 2.5,
                "ja3_hash": "cd08e31494f9531f560d64cfa3f2233c",
                "ja3_threat": False,
                "packet_lengths": g["packet_lengths"],
                "packet_directions": g["packet_directions"],
                "packet_timestamps": ts,
                "duration": dur,
                "total_packets": len(g["packet_lengths"]),
                "total_bytes": sum(g["packet_lengths"])
            })
            flow_idx += 1
        return flows

    def _parse_zeek_csv(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Parses Zeek conn.log CSV."""
        cols_map = {str(c).lower().strip(): c for c in df.columns}
        flows = []
        for idx, row in df.iterrows():
            s_ip = str(row.get(cols_map.get("id.orig_h", "id.orig_h"), "192.168.1.10"))
            d_ip = str(row.get(cols_map.get("id.resp_h", "id.resp_h"), "104.244.42.1"))
            s_port = int(row.get(cols_map.get("id.orig_p", "id.orig_p"), 51234))
            d_port = int(row.get(cols_map.get("id.resp_p", "id.resp_p"), 443))
            dur = max(float(row.get(cols_map.get("duration", "duration"), 3.5)), 0.01)
            orig_b = float(row.get(cols_map.get("orig_bytes", "orig_bytes"), 1200.0))
            resp_b = float(row.get(cols_map.get("resp_bytes", "resp_bytes"), 8500.0))
            orig_p = int(row.get(cols_map.get("orig_pkts", "orig_pkts"), 12))
            resp_p = int(row.get(cols_map.get("resp_pkts", "resp_pkts"), 18))
            tot_p = orig_p + resp_p
            tot_b = orig_b + resp_b
            pcr = (orig_b - resp_b) / max(tot_b, 1.0)

            flows.append({
                "flow_id": f"ZEEK-FLW-{idx+1:04d}",
                "timestamp": float(row.get(cols_map.get("ts", "ts"), time.time())),
                "src_ip": s_ip,
                "src_port": s_port,
                "dst_ip": d_ip,
                "dst_port": d_port,
                "proto": "TLS",
                "sni": f"zeek-conn-{d_ip}",
                "sni_entropy": 2.4,
                "ja3_hash": "cd08e31494f9531f560d64cfa3f2233c",
                "ja3_threat": False,
                "packet_lengths": [int(tot_b / max(tot_p, 1))] * tot_p,
                "packet_directions": [1] * orig_p + [-1] * resp_p,
                "packet_timestamps": [time.time() + (i * dur / max(tot_p, 1)) for i in range(tot_p)],
                "duration": dur,
                "total_packets": tot_p,
                "total_bytes": tot_b
            })
        return flows

    def _parse_json_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Parses JSON or JSONL flow files, or Suricata EVE JSON."""
        flows = []
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read().strip()

        records = []
        if content.startswith("[") and content.endswith("]"):
            records = json.loads(content)
        else:
            # Line-delimited JSON (JSONL)
            for line in content.splitlines():
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except Exception:
                        pass

        for idx, item in enumerate(records):
            # Check Suricata EVE format
            if "event_type" in item:
                s_ip = item.get("src_ip", "192.168.1.100")
                d_ip = item.get("dest_ip", "104.244.42.1")
                s_port = item.get("src_port", 51234)
                d_port = item.get("dest_port", 443)
                tls_data = item.get("tls", {})
                sni = tls_data.get("sni", "suricata-event.net")
                ja3 = tls_data.get("ja3", {}).get("hash", "cd08e31494f9531f560d64cfa3f2233c") if isinstance(tls_data.get("ja3"), dict) else "cd08e31494f9531f560d64cfa3f2233c"

                flow_dict = {
                    "flow_id": f"SURI-FLW-{idx+1:04d}",
                    "timestamp": time.time(),
                    "src_ip": s_ip,
                    "src_port": s_port,
                    "dst_ip": d_ip,
                    "dst_port": d_port,
                    "proto": "TLS",
                    "sni": sni,
                    "sni_entropy": analyze_sni(sni)["entropy"],
                    "ja3_hash": ja3,
                    "ja3_threat": bool(lookup_ja3(ja3) and lookup_ja3(ja3)["risk_level"] in ["CRITICAL", "HIGH"]),
                    "packet_lengths": [120, 1400, 1400, 120, 1400],
                    "packet_directions": [1, -1, -1, 1, -1],
                    "packet_timestamps": [time.time() + (i * 0.2) for i in range(5)],
                    "duration": 1.0,
                    "total_packets": 5,
                    "total_bytes": 4440
                }
            else:
                # Direct flow dictionary
                flow_dict = item.copy()
                if "flow_id" not in flow_dict:
                    flow_dict["flow_id"] = f"JSON-FLW-{idx+1:04d}"
                if "packet_lengths" not in flow_dict:
                    tot_pkts = int(flow_dict.get("total_packets", 25))
                    tot_bytes = float(flow_dict.get("total_bytes", 12000))
                    flow_dict["packet_lengths"] = [int(tot_bytes / max(tot_pkts, 1))] * tot_pkts
                    flow_dict["packet_directions"] = [1 if i % 2 == 0 else -1 for i in range(tot_pkts)]
                    dur = float(flow_dict.get("duration", flow_dict.get("flow_duration", 3.0)))
                    flow_dict["packet_timestamps"] = [time.time() + (i * dur / max(tot_pkts, 1)) for i in range(tot_pkts)]

            flows.append(flow_dict)

        return flows

    def _parse_zeek_log_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Parses native Zeek tab-delimited conn.log file."""
        lines = []
        fields = []
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#fields"):
                    fields = line.split()[1:]
                elif not line.startswith("#") and line:
                    lines.append(line.split("\t"))

        if not fields:
            fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes"]

        records = []
        for l in lines:
            if len(l) == len(fields):
                records.append(dict(zip(fields, l)))

        return self._parse_zeek_csv(pd.DataFrame(records))

    def _parse_parquet_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Parses Parquet flow dataset."""
        df = pd.read_parquet(filepath)
        return self._parse_csv_file(filepath)  # Same row mapping


def generate_sample_flow_csv(output_filepath: str):
    """Generates a sample CSV flow dataset for instant testing."""
    rows = [
        {"flow_id": "CSV-001", "src_ip": "192.168.1.105", "dst_ip": "140.82.121.4", "src_port": 52140, "dst_port": 443, "sni": "api.github.com", "total_packets": 45, "total_bytes": 32000, "flow_duration": 4.5, "pcr": -0.72, "label": "BENIGN_WEB"},
        {"flow_id": "CSV-002", "src_ip": "192.168.1.112", "dst_ip": "185.220.101.5", "src_port": 49812, "dst_port": 443, "sni": "cdn-c2-update.top", "total_packets": 16, "total_bytes": 3800, "flow_duration": 35.0, "pcr": 0.08, "label": "C2_BEACONING"},
        {"flow_id": "CSV-003", "src_ip": "192.168.1.144", "dst_ip": "45.154.255.8", "src_port": 55100, "dst_port": 443, "sni": "s3-vault-exfil.xyz", "total_packets": 420, "total_bytes": 590000, "flow_duration": 12.0, "pcr": 0.94, "label": "DATA_EXFILTRATION"},
        {"flow_id": "CSV-004", "src_ip": "192.168.1.189", "dst_ip": "194.26.29.112", "src_port": 53000, "dst_port": 9001, "sni": "", "total_packets": 110, "total_bytes": 78000, "flow_duration": 22.0, "pcr": 0.02, "label": "TOR_PROXY_TUNNEL"},
        {"flow_id": "CSV-005", "src_ip": "192.168.1.201", "dst_ip": "1.1.1.1", "src_port": 54200, "dst_port": 443, "sni": "7a94f1c98a0029b.doh-tunnel.xyz", "total_packets": 65, "total_bytes": 18500, "flow_duration": 15.0, "pcr": 0.35, "label": "DOH_DATA_TUNNEL"}
    ]
    pd.DataFrame(rows).to_csv(output_filepath, index=False)
    return output_filepath


def generate_sample_flow_json(output_filepath: str):
    """Generates a sample JSON flow dataset for instant testing."""
    records = [
        {"flow_id": "JSON-001", "src_ip": "192.168.1.100", "dst_ip": "172.217.16.206", "src_port": 51000, "dst_port": 443, "sni": "www.google.com", "total_packets": 32, "total_bytes": 24000, "duration": 3.2, "pcr": -0.65, "ja3_hash": "cd08e31494f9531f560d64cfa3f2233c"},
        {"flow_id": "JSON-002", "src_ip": "192.168.1.105", "dst_ip": "185.220.101.5", "src_port": 51240, "dst_port": 443, "sni": "beacon.apt-c2.top", "total_packets": 12, "total_bytes": 3200, "duration": 30.0, "pcr": 0.05, "ja3_hash": "a0e9f5d64349fb13191bc781f81f42e1"},
        {"flow_id": "JSON-003", "src_ip": "192.168.1.189", "dst_ip": "45.154.255.8", "src_port": 54100, "dst_port": 443, "sni": "dropzone.cloud-s3.xyz", "total_packets": 350, "total_bytes": 490000, "duration": 9.5, "pcr": 0.92, "ja3_hash": "51c64c77e60f3980eea90869b68c58a8"}
    ]
    with open(output_filepath, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)
    return output_filepath
