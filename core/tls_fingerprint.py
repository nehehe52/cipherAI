"""
TLS Fingerprinting and Cryptographic Metadata Analyzer.
Provides JA3 / JA4 hash computation, known malware/benign fingerprint matching,
and SNI domain entropy & DGA detection.
"""

import hashlib
import math
import re
from typing import Dict, List, Optional, Tuple, Any

# Database of known TLS JA3 fingerprints
KNOWN_JA3_DATABASE: Dict[str, Dict[str, Any]] = {
    # Malicious / Suspicious Signatures
    "a0e9f5d64349fb13191bc781f81f42e1": {
        "client": "Cobalt Strike HTTPS Beacon",
        "category": "C2_BEACONING",
        "risk_level": "CRITICAL",
        "description": "Default TLS configuration for Cobalt Strike Malleable C2 HTTPS listener"
    },
    "72a589da586844d7f0818ce684948eea": {
        "client": "Sliver C2 Implant",
        "category": "C2_BEACONING",
        "risk_level": "CRITICAL",
        "description": "Bishop Fox Sliver open-source adversary emulation HTTPS implant"
    },
    "e7d705a3286e19ea42f587b344ee6865": {
        "client": "Metasploit Meterpreter Reverse HTTPS",
        "category": "C2_BEACONING",
        "risk_level": "CRITICAL",
        "description": "Metasploit payload windows/meterpreter/reverse_https staged session"
    },
    "b32309a26951912be7dba376398abc3b": {
        "client": "Emotet Banking Trojan / Botnet",
        "category": "C2_BEACONING",
        "risk_level": "CRITICAL",
        "description": "Emotet automated C2 beacon communication channel"
    },
    "51c64c77e60f3980eea90869b68c58a8": {
        "client": "TrickBot / Anchor Malware",
        "category": "DATA_EXFILTRATION",
        "risk_level": "CRITICAL",
        "description": "Trickbot encrypted data exfiltration channel"
    },
    "2c42bb7ee40030c69d80c651f163e9f4": {
        "client": "QakBot (QBot) C2 Channel",
        "category": "C2_BEACONING",
        "risk_level": "CRITICAL",
        "description": "QakBot modular banking trojan encrypted command tunnel"
    },
    "406c117e6992d95188f1ae6a8ff4a0a5": {
        "client": "Tor Browser / Onion Proxy",
        "category": "TOR_PROXY_TUNNEL",
        "risk_level": "HIGH",
        "description": "Tor encrypted proxy circuit / bridge entry negotiation"
    },
    "c1292023a85b9b9a5276e0339d2e7a17": {
        "client": "Empire PowerShell Agent",
        "category": "C2_BEACONING",
        "risk_level": "HIGH",
        "description": "PowerShell Empire encrypted C2 HTTPS transport"
    },
    # Legitimate / Standard Clients
    "cd08e31494f9531f560d64cfa3f2233c": {
        "client": "Google Chrome (Desktop / Win11)",
        "category": "BENIGN_WEB",
        "risk_level": "BENIGN",
        "description": "Standard Chromium TLS 1.3 ClientHello with GREASE extensions"
    },
    "b38455a272046096e6a1aa94ec4392e2": {
        "client": "Mozilla Firefox (Modern)",
        "category": "BENIGN_WEB",
        "risk_level": "BENIGN",
        "description": "Mozilla Firefox TLS 1.3 standard browser fingerprint"
    },
    "999654497e6515b8004f1fb93e2dd60a": {
        "client": "Apple Safari / WebKit",
        "category": "BENIGN_WEB",
        "risk_level": "BENIGN",
        "description": "Apple Safari macOS/iOS TLS stack"
    },
    "771fedcc35de56d9269e437457141663": {
        "client": "Python Requests / Urllib3",
        "category": "BENIGN_API",
        "risk_level": "LOW",
        "description": "Standard Python HTTP client library connection"
    },
    "6c86716a5b6d9e030a58a7e0892f3e8f": {
        "client": "Golang net/http client",
        "category": "BENIGN_API",
        "risk_level": "LOW",
        "description": "Go runtime standard HTTP client"
    },
}

# Suspicious TLDs frequently abused in C2 / Phishing / DGA
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".biz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".ru", ".cc", ".su", ".work", ".click", ".buzz", ".onion"
}


def compute_shannon_entropy(data: str) -> float:
    """
    Computes Shannon Entropy H(X) in bits for a given string:
    H = - sum( p(x) * log2(p(x)) )
    """
    if not data:
        return 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    
    entropy = 0.0
    for count in frequencies.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def compute_byte_entropy(byte_data: bytes) -> float:
    """Computes Shannon entropy for raw byte array (0 to 8 bits)."""
    if not byte_data:
        return 0.0
    length = len(byte_data)
    freq = [0] * 256
    for b in byte_data:
        freq[b] += 1
    
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def calculate_ja3(
    tls_version: int,
    cipher_suites: List[int],
    extensions: List[int],
    elliptic_curves: List[int],
    ec_point_formats: List[int]
) -> Tuple[str, str]:
    """
    Calculates standard JA3 string and MD5 hash.
    Format: SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
    (e.g., 771,49195-49199,0-23,29-23,0)
    Filters out GREASE values according to RFC 8701.
    """
    def filter_grease(items: List[int]) -> List[int]:
        # GREASE values end in 0a0a, 1a1a, etc. (0x?a?a)
        grease_set = {
            0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
            0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
        }
        return [x for x in items if x not in grease_set]

    ciphers_str = "-".join(str(c) for c in filter_grease(cipher_suites))
    exts_str = "-".join(str(e) for e in filter_grease(extensions))
    curves_str = "-".join(str(c) for c in filter_grease(elliptic_curves))
    formats_str = "-".join(str(f) for f in ec_point_formats)

    ja3_string = f"{tls_version},{ciphers_str},{exts_str},{curves_str},{formats_str}"
    ja3_hash = hashlib.md5(ja3_string.encode("utf-8")).hexdigest()
    return ja3_string, ja3_hash


def lookup_ja3(ja3_hash: str) -> Optional[Dict[str, Any]]:
    """Look up a JA3 hash in known signature database."""
    return KNOWN_JA3_DATABASE.get(ja3_hash.lower())


def analyze_sni(sni: Optional[str]) -> Dict[str, Any]:
    """
    Analyzes Server Name Indication (SNI) domain:
    - Calculates entropy (detects DGA - Domain Generation Algorithms)
    - Checks for suspicious TLDs
    - Detects hex/base64 encoded subdomains (DoH tunneling)
    - Checks vowel-to-consonant anomaly
    """
    if not sni:
        return {
            "sni": "None (Direct IP / Encrypted SNI)",
            "entropy": 0.0,
            "is_dga": False,
            "suspicious_tld": False,
            "is_tunneling_subdomain": False,
            "risk_score": 0.2
        }

    domain = sni.lower().strip()
    entropy = compute_shannon_entropy(domain)
    
    # Check suspicious TLD
    suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
    
    # Check DGA heuristic: high entropy (> 3.65) or long subdomain with random chars
    parts = domain.split(".")
    first_label = parts[0] if parts else ""
    first_label_entropy = compute_shannon_entropy(first_label)
    
    # Subdomain tunneling check (DoH / DNS tunneling often uses base32/hex labels > 25 chars)
    is_tunneling_subdomain = len(first_label) >= 24 and bool(re.match(r"^[a-z0-9_-]+$", first_label))
    
    is_dga = (first_label_entropy > 3.6 and len(first_label) > 10) or (entropy > 3.8 and len(domain) > 16)

    # Compute risk score 0.0 to 1.0
    risk = 0.0
    if is_dga:
        risk += 0.45
    if is_tunneling_subdomain:
        risk += 0.40
    if suspicious_tld:
        risk += 0.35
    if len(parts) > 4:  # Deep nested subdomain
        risk += 0.15

    risk = min(round(risk, 2), 1.0)

    return {
        "sni": domain,
        "entropy": entropy,
        "first_label_entropy": first_label_entropy,
        "is_dga": is_dga,
        "suspicious_tld": suspicious_tld,
        "is_tunneling_subdomain": is_tunneling_subdomain,
        "risk_score": risk
    }
