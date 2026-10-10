"""
Comprehensive Test Suite for AI Threat Detection & Real-Time Anomaly Analysis.
Validates Feature Extraction, TLS Fingerprinting, AI Models, PCAP Parsing, and SOAR Mitigation.
"""

import os
import unittest
import numpy as np

from core.tls_fingerprint import calculate_ja3, lookup_ja3, compute_shannon_entropy, analyze_sni
from core.feature_extractor import extract_flow_features, FEATURE_NAMES
from core.ai_engine import EncryptedThreatAIEngine
from core.traffic_generator import EncryptedTrafficGenerator
from core.mitigation_engine import MitigationEngine
from core.pcap_analyzer import PCAPAnalyzer, generate_sample_pcap


class TestEncryptedThreatDetection(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ai_engine = EncryptedThreatAIEngine()
        cls.generator = EncryptedTrafficGenerator()
        cls.mitigation = MitigationEngine()

    def test_tls_fingerprint_and_ja3(self):
        """Verify JA3 computation and database lookup."""
        # Simulated Cobalt Strike ClientHello parameters
        raw_str, ja3_hash = calculate_ja3(
            tls_version=771,
            cipher_suites=[49195, 49199, 49196, 49200],
            extensions=[0, 23, 65281, 10, 11],
            elliptic_curves=[29, 23, 24],
            ec_point_formats=[0]
        )
        self.assertIsInstance(ja3_hash, str)
        self.assertEqual(len(ja3_hash), 32)

        # Known Cobalt Strike lookup
        cs_meta = lookup_ja3("a0e9f5d64349fb13191bc781f81f42e1")
        self.assertIsNotNone(cs_meta)
        self.assertEqual(cs_meta["category"], "C2_BEACONING")
        self.assertEqual(cs_meta["risk_level"], "CRITICAL")

    def test_sni_entropy_and_dga(self):
        """Verify DGA and high-entropy domain detection."""
        legit = analyze_sni("www.google.com")
        self.assertFalse(legit["is_dga"])
        self.assertLess(legit["entropy"], 3.2)

        dga = analyze_sni("x9zq2p48lkmv01a938.top")
        self.assertTrue(dga["is_dga"] or dga["suspicious_tld"])
        self.assertGreater(dga["risk_score"], 0.4)

    def test_feature_extraction_dimension(self):
        """Ensure feature extraction output matches defined schema exactly."""
        sample_flow = self.generator.generate_benign_flow()
        features = extract_flow_features(sample_flow)
        
        self.assertEqual(len(features), len(FEATURE_NAMES))
        for feat in FEATURE_NAMES:
            self.assertIn(feat, features)
            self.assertIsInstance(features[feat], (int, float))

    def test_c2_beaconing_detection(self):
        """Ensure periodic C2 beaconing is detected with high anomaly score and proper class."""
        c2_flow = self.generator.generate_c2_beacon()
        result = self.ai_engine.analyze_flow(c2_flow)
        
        self.assertIn(result["predicted_threat"], ["C2_BEACONING", "ANOMALOUS_UNKNOWN"])
        self.assertGreaterEqual(result["anomaly_score"], 0.65)
        self.assertTrue(result["is_anomaly"])
        self.assertGreater(len(result["xai_explanation"]), 0)

    def test_data_exfiltration_detection(self):
        """Ensure heavy outbound TLS upload is detected as Data Exfiltration."""
        exfil_flow = self.generator.generate_exfiltration()
        result = self.ai_engine.analyze_flow(exfil_flow)
        
        self.assertEqual(result["predicted_threat"], "DATA_EXFILTRATION")
        self.assertGreaterEqual(result["anomaly_score"], 0.60)
        self.assertGreater(result["features"]["pcr"], 0.70)

    def test_mitigation_and_quarantine(self):
        """Verify firewall rule generation and IP quarantine registry."""
        ip = "185.220.101.5"
        entry = self.mitigation.quarantine_ip(
            ip=ip,
            threat_type="C2_BEACONING",
            anomaly_score=0.92,
            details="Cobalt Strike HTTPS Beaconing detected with JA3 match"
        )
        self.assertTrue(self.mitigation.is_quarantined(ip))
        self.assertIn("windows_netsh", entry["firewall_rules"])
        self.assertIn("linux_iptables", entry["firewall_rules"])
        self.assertIn(ip, entry["firewall_rules"]["windows_netsh"])

        # Release IP
        released = self.mitigation.release_ip(ip)
        self.assertTrue(released)
        self.assertFalse(self.mitigation.is_quarantined(ip))

    def test_pcap_parsing_pipeline(self):
        """Verify reading and feature extraction from PCAP capture."""
        test_pcap = "test_run.pcap"
        generate_sample_pcap(test_pcap)
        self.assertTrue(os.path.exists(test_pcap))

        analyzer = PCAPAnalyzer()
        flows = analyzer.analyze_pcap_file(test_pcap)
        self.assertGreater(len(flows), 0)

        for flow in flows:
            res = self.ai_engine.analyze_flow(flow)
            self.assertIn("predicted_threat", res)
            self.assertIn("anomaly_score", res)

        if os.path.exists(test_pcap):
            os.remove(test_pcap)

    def test_dataset_manager_catalog_and_evaluation(self):
        """Verify standard datasets load and evaluate correctly."""
        from core.dataset_manager import DatasetManager
        dm = DatasetManager()
        datasets = dm.list_datasets()
        self.assertIn("ctu13_botnet_tls", datasets)
        self.assertIn("cira_cic_doh_tunneling", datasets)

        df = dm.load_dataset("ctu13_botnet_tls")
        self.assertGreater(len(df), 100)
        self.assertIn("label", df.columns)

        # Test evaluation
        eval_res = dm.evaluate_model(df.head(200), self.ai_engine)
        self.assertIn("accuracy", eval_res)
        self.assertGreater(eval_res["accuracy"], 0.85)
        self.assertIn("confusion_matrix", eval_res)

        # Test PCAP list
        pcaps = dm.list_pcaps()
        self.assertGreaterEqual(len(pcaps), 5)


    def test_live_network_monitor_guard(self):
        """Verify the live traffic guard serves, rate-limits a flood source, and reconfigures at runtime."""
        import time
        from core.live_network_monitor import LiveNetworkMonitor
        monitor = LiveNetworkMonitor(guard_port=0).start()
        try:
            monitor.target_rps = 60
            monitor.flood_enabled = True
            monitor.flood_rps = 60
            time.sleep(3)
            snap = monitor.snapshot()
            self.assertGreater(snap["totals"].get("2xx", 0), 0)
            self.assertGreater(snap["totals"].get("rate_limited", 0), 0)
            self.assertIsNotNone(snap["last_10s"]["latency_ms"]["p50"])
            self.assertEqual(len(snap["timeseries"]), 60)

            monitor.configure_guard(rate=500, burst=500, max_concurrency=8, max_queue=4,
                                    queue_timeout=0.1, upstream_timeout=1.0)
            limits = monitor.snapshot()["limits"]
            self.assertEqual(limits["max_concurrency"], 8)
            self.assertEqual(limits["rate"], 500)
        finally:
            monitor.stop()


if __name__ == "__main__":
    unittest.main()
