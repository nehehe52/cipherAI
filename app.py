"""
AI-Powered Automated Threat Detection & Real-Time Anomaly Analysis in Encrypted Network Traffic.
Cyber Defense Operations Center Dashboard.
"""

import time
import os
import io
import json
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from core.ai_engine import EncryptedThreatAIEngine, THREAT_LABELS
from core.traffic_generator import EncryptedTrafficGenerator
from core.mitigation_engine import MitigationEngine, MITRE_MAPPING
from core.tls_fingerprint import lookup_ja3, analyze_sni
from core.pcap_analyzer import PCAPAnalyzer, generate_sample_pcap
from core.dataset_manager import DatasetManager, DATASET_METADATA
from core.file_ingestor import UniversalFileIngestor, generate_sample_flow_csv, generate_sample_flow_json

# ==========================================
# Page Configuration & Modern SOC Dark Theme
# ==========================================
st.set_page_config(
    page_title="AI Encrypted Threat Detection & Real-Time SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom High-Tech Cyber Security SOC Styling
st.markdown("""
<style>
    /* Dark Theme Cyber Palette */
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
    }
    
    /* Metrics Card */
    .metric-box {
        background: linear-gradient(135deg, rgba(20, 27, 45, 0.8), rgba(15, 23, 42, 0.95));
        border: 1px solid rgba(56, 189, 248, 0.2);
        border-radius: 10px;
        padding: 16px;
        box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.5);
        backdrop-filter: blur(8px);
    }
    .metric-title {
        font-size: 0.82rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #94a3b8;
        font-weight: 600;
        margin-bottom: 4px;
    }
    .metric-val {
        font-size: 1.85rem;
        font-weight: 700;
        color: #38bdf8;
        font-family: 'Courier New', monospace;
    }
    .metric-sub {
        font-size: 0.75rem;
        color: #64748b;
        margin-top: 4px;
    }

    /* Severity Badges */
    .badge-critical {
        background-color: rgba(239, 68, 68, 0.2);
        color: #ef4444;
        border: 1px solid #ef4444;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.75rem;
    }
    .badge-high {
        background-color: rgba(249, 115, 22, 0.2);
        color: #f97316;
        border: 1px solid #f97316;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.75rem;
    }
    .badge-medium {
        background-color: rgba(234, 179, 8, 0.2);
        color: #eab308;
        border: 1px solid #eab308;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.75rem;
    }
    .badge-benign {
        background-color: rgba(34, 197, 94, 0.2);
        color: #22c55e;
        border: 1px solid #22c55e;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.75rem;
    }

    /* Status indicator */
    .status-pill {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 20px;
        font-size: 0.78rem;
        font-weight: 600;
        letter-spacing: 0.05em;
    }
    .status-online {
        background: rgba(34, 197, 94, 0.15);
        color: #4ade80;
        border: 1px solid rgba(34, 197, 94, 0.4);
    }
</style>
""", unsafe_allow_html=True)


# ==========================================
# Audio Alert Synthesizer (PCM WAV & Web Audio API)
# ==========================================
def generate_beep_wav_b64(freq1: int = 880, freq2: int = 1320) -> str:
    """Generates a crisp cyber alarm dual-tone PCM audio wave encoded in base64."""
    import io, wave, struct, math, base64
    sample_rate = 22050
    buf = io.BytesIO()
    with wave.open(buf, 'wb') as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        # Beep pulse 1 (880 Hz)
        for i in range(int(sample_rate * 0.10)):
            val = int(32767 * 0.45 * math.sin(2 * math.pi * freq1 * i / sample_rate))
            wf.writeframes(struct.pack('<h', val))
        # Silence gap (0.03s)
        for _ in range(int(sample_rate * 0.03)):
            wf.writeframes(struct.pack('<h', 0))
        # Beep pulse 2 (1320 Hz high alert tone)
        for i in range(int(sample_rate * 0.14)):
            val = int(32767 * 0.50 * math.sin(2 * math.pi * freq2 * i / sample_rate))
            wf.writeframes(struct.pack('<h', val))
    return base64.b64encode(buf.getvalue()).decode('utf-8')

ALERT_BEEP_B64 = generate_beep_wav_b64()

def play_anomaly_beep():
    """Plays audible dual-tone alert beep using HTML5 Audio and Web Audio API synthesizer."""
    import streamlit.components.v1 as components
    html_audio = f"""
    <audio autoplay style="display:none;">
        <source src="data:audio/wav;base64,{ALERT_BEEP_B64}" type="audio/wav">
    </audio>
    <script>
    (function() {{
        try {{
            const AudioCtx = window.AudioContext || window.webkitAudioContext;
            if (AudioCtx) {{
                const ctx = new AudioCtx();
                const now = ctx.currentTime;
                // Tone 1
                const osc1 = ctx.createOscillator();
                const gain1 = ctx.createGain();
                osc1.type = 'sawtooth';
                osc1.frequency.setValueAtTime(880, now);
                gain1.gain.setValueAtTime(0.4, now);
                gain1.gain.exponentialRampToValueAtTime(0.01, now + 0.11);
                osc1.connect(gain1);
                gain1.connect(ctx.destination);
                osc1.start(now);
                osc1.stop(now + 0.11);

                // Tone 2
                const osc2 = ctx.createOscillator();
                const gain2 = ctx.createGain();
                osc2.type = 'sawtooth';
                osc2.frequency.setValueAtTime(1320, now + 0.13);
                gain2.gain.setValueAtTime(0.45, now + 0.13);
                gain2.gain.exponentialRampToValueAtTime(0.01, now + 0.27);
                osc2.connect(gain2);
                gain2.connect(ctx.destination);
                osc2.start(now + 0.13);
                osc2.stop(now + 0.27);
            }}
        }} catch(e) {{
            console.error("Audio playback error:", e);
        }}
    }})();
    </script>
    """
    components.html(html_audio, height=0, width=0)


# ==========================================
# Session State Initialization
# ==========================================
if "ai_engine" not in st.session_state:
    with st.spinner("Initializing AI Threat Detection Engine & Pre-Trained Models..."):
        st.session_state.ai_engine = EncryptedThreatAIEngine()

if "traffic_gen" not in st.session_state:
    st.session_state.traffic_gen = EncryptedTrafficGenerator()

if "mitigation_engine" not in st.session_state:
    st.session_state.mitigation_engine = MitigationEngine()

if "dataset_manager" not in st.session_state:
    st.session_state.dataset_manager = DatasetManager()

if "stream_flows" not in st.session_state:
    st.session_state.stream_flows = []

if "stream_results" not in st.session_state:
    st.session_state.stream_results = []

if "is_streaming" not in st.session_state:
    st.session_state.is_streaming = False

if "pcap_results" not in st.session_state:
    st.session_state.pcap_results = None

if "selected_flow_detail" not in st.session_state:
    st.session_state.selected_flow_detail = None

if "audio_alerts_enabled" not in st.session_state:
    st.session_state.audio_alerts_enabled = True

if "play_beep_pending" not in st.session_state:
    st.session_state.play_beep_pending = False


# ==========================================
# Sidebar: Navigation & Operational Controls
# ==========================================
st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=64)
st.sidebar.title("SOC Control Console")
st.sidebar.caption("Encrypted Traffic Analytics (ETA) v2.0")

app_mode = st.sidebar.radio(
    "Operational Module",
    [
        "⚡ Real-Time Live Traffic Stream",
        "📁 Multi-Format File Ingestion (PCAP, CSV, JSON, LOG)",
        "📊 Benchmark Datasets & Model Training Lab",
        "🧪 Threat Simulator & Attack Sandbox",
        "🛡️ Active Quarantine & SOAR Rules",
        "📚 MITRE ATT&CK Matrix & Threat Intel"
    ],
    index=0
)

st.sidebar.markdown("---")
st.sidebar.subheader("AI Engine Parameters")
anomaly_threshold = st.sidebar.slider(
    "Anomaly Sensitivity Threshold",
    min_value=0.30,
    max_value=0.95,
    value=0.60,
    step=0.05,
    help="Threshold above which flows are flagged as anomalies by the unsupervised Isolation Forest."
)

st.sidebar.markdown("""
<div style='background: rgba(15, 23, 42, 0.6); padding: 10px; border-radius: 8px; border: 1px solid #334155;'>
    <div style='font-size: 0.8rem; color: #94a3b8;'>Engine Status:</div>
    <div style='color: #22c55e; font-weight: bold;'>● DUAL-STAGE AI READY</div>
    <div style='font-size: 0.75rem; color: #64748b; margin-top: 4px;'>• Unsupervised: Isolation Forest<br>• Supervised: RF Threat Classifier<br>• JA3/JA4 Cryptographic Matcher</div>
</div>
""", unsafe_allow_html=True)

st.sidebar.markdown("---")
st.sidebar.subheader("🔊 Audio Threat Siren")
audio_toggle = st.sidebar.toggle(
    "Audible Anomaly Beep",
    value=st.session_state.get("audio_alerts_enabled", True),
    help="Plays an audible dual-tone alert beep whenever an anomaly or threat is detected."
)
st.session_state.audio_alerts_enabled = audio_toggle

if st.sidebar.button("🔔 Test Anomaly Beep Sound", use_container_width=True):
    st.session_state.play_beep_pending = True
    st.rerun()


# ==========================================
# Header Banner
# ==========================================
header_col1, header_col2 = st.columns([3, 1])
with header_col1:
    st.markdown("""
    <h2 style='margin-bottom: 0px;'>🛡️ AI-Powered Automated Threat Detection & Real-Time Anomaly Analysis</h2>
    <p style='color: #94a3b8; font-size: 0.95rem; margin-top: 4px;'>
        Real-Time Deep Inspection of Encrypted Network Traffic (TLS 1.2 / 1.3, HTTPS, SSH, DoH, Tor) without Decryption.
    </p>
    """, unsafe_allow_html=True)

with header_col2:
    st.markdown(f"""
    <div style='text-align: right; padding-top: 10px;'>
        <span class='status-pill status-online'>● ACTIVE DEFENSE ARMED</span>
        <div style='font-size: 0.75rem; color: #64748b; margin-top: 4px;'>
            Quarantined Targets: <b>{len(st.session_state.mitigation_engine.quarantined_ips)}</b>
        </div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# Audible Alert Trigger: Plays browser audio alert if an anomaly was flagged
if st.session_state.get("play_beep_pending", False):
    if st.session_state.get("audio_alerts_enabled", True):
        play_anomaly_beep()
        st.toast("🚨 ANOMALY DETECTED: Cyber Threat Audible Alert Triggered!", icon="🚨")
    st.session_state.play_beep_pending = False


# ==============================================================================
# Helper Functions for Visualizations & Display
# ==============================================================================
def render_metric_cards(flows_list, results_list):
    """Renders high-impact SOC summary KPI cards."""
    total_flows = len(flows_list)
    if total_flows == 0:
        anomalies = 0
        critical_high = 0
        total_mbytes = 0.0
        exfil_mbytes = 0.0
    else:
        anomalies = sum(1 for r in results_list if r["is_anomaly"])
        critical_high = sum(
            1 for r in results_list 
            if r["predicted_threat"] in ["C2_BEACONING", "DATA_EXFILTRATION", "TOR_PROXY_TUNNEL"]
        )
        total_bytes = sum(f.get("total_bytes", 0) for f in flows_list)
        total_mbytes = round(total_bytes / (1024 * 1024), 2)
        exfil_bytes = sum(
            f.get("total_bytes", 0) for f, r in zip(flows_list, results_list)
            if r["predicted_threat"] == "DATA_EXFILTRATION"
        )
        exfil_mbytes = round(exfil_bytes / (1024 * 1024), 2)

    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.markdown(f"""
        <div class='metric-box'>
            <div class='metric-title'>Encrypted Flows</div>
            <div class='metric-val'>{total_flows}</div>
            <div class='metric-sub'>Active TLS Sessions</div>
        </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
        <div class='metric-box'>
            <div class='metric-title'>Anomalies Flagged</div>
            <div class='metric-val' style='color: {"#ef4444" if anomalies > 0 else "#22c55e"};'>{anomalies}</div>
            <div class='metric-sub'>Deviation Score &ge; {anomaly_threshold}</div>
        </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown(f"""
        <div class='metric-box'>
            <div class='metric-title'>Critical/High Threats</div>
            <div class='metric-val' style='color: {"#f97316" if critical_high > 0 else "#22c55e"};'>{critical_high}</div>
            <div class='metric-sub'>C2 / Exfil / Tor Tunnels</div>
        </div>
        """, unsafe_allow_html=True)
    with c4:
        st.markdown(f"""
        <div class='metric-box'>
            <div class='metric-title'>Total Monitored Vol</div>
            <div class='metric-val' style='color: #38bdf8;'>{total_mbytes} MB</div>
            <div class='metric-sub'>Encrypted Flow Volume</div>
        </div>
        """, unsafe_allow_html=True)
    with c5:
        st.markdown(f"""
        <div class='metric-box'>
            <div class='metric-title'>Quarantined IPs</div>
            <div class='metric-val' style='color: {"#ec4899" if len(st.session_state.mitigation_engine.quarantined_ips) > 0 else "#94a3b8"};'>{len(st.session_state.mitigation_engine.quarantined_ips)}</div>
            <div class='metric-sub'>Active Firewall Drops</div>
        </div>
        """, unsafe_allow_html=True)


def get_threat_badge(threat_type: str) -> str:
    """Returns styled HTML badge for a threat label."""
    mitre = st.session_state.mitigation_engine.get_mitre_info(threat_type)
    sev = mitre["severity"]
    if sev == "CRITICAL":
        return f"<span class='badge-critical'>🚨 {threat_type}</span>"
    elif sev == "HIGH":
        return f"<span class='badge-high'>⚠️ {threat_type}</span>"
    elif sev == "MEDIUM":
        return f"<span class='badge-medium'>⚡ {threat_type}</span>"
    else:
        return f"<span class='badge-benign'>✓ {threat_type}</span>"


# ==============================================================================
# MODULE 1: REAL-TIME LIVE TRAFFIC STREAM
# ==============================================================================
if app_mode == "⚡ Real-Time Live Traffic Stream":
    st.subheader("⚡ Real-Time Encrypted Traffic Telemetry & Attack Detection")

    # Interactive Attack Injector & Streaming Controls
    ctrl_col1, ctrl_col2 = st.columns([1.5, 2.5])
    with ctrl_col1:
        st.markdown("##### 📡 Stream Controls")
        stream_b1, stream_b2, stream_b3 = st.columns(3)
        with stream_b1:
            if st.button("▶ Stream 5 Flows", use_container_width=True):
                any_anomaly = False
                for _ in range(5):
                    choice = np.random.choice(["benign", "streaming", "c2", "exfil", "tor", "doh"], p=[0.55, 0.20, 0.10, 0.05, 0.05, 0.05])
                    if choice == "benign":
                        f = st.session_state.traffic_gen.generate_benign_flow("web")
                    elif choice == "streaming":
                        f = st.session_state.traffic_gen.generate_benign_flow("streaming")
                    elif choice == "c2":
                        f = st.session_state.traffic_gen.generate_c2_beacon()
                    elif choice == "exfil":
                        f = st.session_state.traffic_gen.generate_exfiltration()
                    elif choice == "tor":
                        f = st.session_state.traffic_gen.generate_tor_tunnel()
                    else:
                        f = st.session_state.traffic_gen.generate_doh_tunnel()
                    res = st.session_state.ai_engine.analyze_flow(f, sensitivity=anomaly_threshold)
                    if res["is_anomaly"]:
                        any_anomaly = True
                    st.session_state.stream_flows.append(f)
                    st.session_state.stream_results.append(res)
                if any_anomaly:
                    st.session_state.play_beep_pending = True
                st.rerun()

        with stream_b2:
            if st.button("⚡ Stream 20 Flows", use_container_width=True):
                any_anomaly = False
                for _ in range(20):
                    choice = np.random.choice(["benign", "streaming", "c2", "exfil", "tor", "doh", "flood"], p=[0.50, 0.20, 0.10, 0.05, 0.05, 0.05, 0.05])
                    if choice == "benign":
                        f = st.session_state.traffic_gen.generate_benign_flow("web")
                    elif choice == "streaming":
                        f = st.session_state.traffic_gen.generate_benign_flow("streaming")
                    elif choice == "c2":
                        f = st.session_state.traffic_gen.generate_c2_beacon()
                    elif choice == "exfil":
                        f = st.session_state.traffic_gen.generate_exfiltration()
                    elif choice == "tor":
                        f = st.session_state.traffic_gen.generate_tor_tunnel()
                    elif choice == "doh":
                        f = st.session_state.traffic_gen.generate_doh_tunnel()
                    else:
                        f = st.session_state.traffic_gen.generate_tls_flood()
                    res = st.session_state.ai_engine.analyze_flow(f, sensitivity=anomaly_threshold)
                    if res["is_anomaly"]:
                        any_anomaly = True
                    st.session_state.stream_flows.append(f)
                    st.session_state.stream_results.append(res)
                if any_anomaly:
                    st.session_state.play_beep_pending = True
                st.rerun()

        with stream_b3:
            if st.button("🗑️ Clear Buffer", use_container_width=True):
                st.session_state.stream_flows.clear()
                st.session_state.stream_results.clear()
                st.session_state.selected_flow_detail = None
                st.rerun()

    with ctrl_col2:
        st.markdown("##### 🎯 Targeted Attack Injection (Test AI Real-Time Response)")
        inj_c1, inj_c2, inj_c3, inj_c4, inj_c5 = st.columns(5)
        with inj_c1:
            if st.button("🔴 C2 Beacon", use_container_width=True, help="Inject Cobalt Strike / Sliver HTTPS Beacon"):
                f = st.session_state.traffic_gen.generate_c2_beacon()
                res = st.session_state.ai_engine.analyze_flow(f, sensitivity=anomaly_threshold)
                st.session_state.play_beep_pending = True
                st.session_state.stream_flows.append(f)
                st.session_state.stream_results.append(res)
                st.rerun()
        with inj_c2:
            if st.button("🔴 S3 Exfil", use_container_width=True, help="Inject High-Volume Encrypted Data Upload"):
                f = st.session_state.traffic_gen.generate_exfiltration()
                res = st.session_state.ai_engine.analyze_flow(f, sensitivity=anomaly_threshold)
                st.session_state.play_beep_pending = True
                st.session_state.stream_flows.append(f)
                st.session_state.stream_results.append(res)
                st.rerun()
        with inj_c3:
            if st.button("🟠 Tor Tunnel", use_container_width=True, help="Inject Tor Multi-hop Onion Circuit"):
                f = st.session_state.traffic_gen.generate_tor_tunnel()
                res = st.session_state.ai_engine.analyze_flow(f, sensitivity=anomaly_threshold)
                st.session_state.play_beep_pending = True
                st.session_state.stream_flows.append(f)
                st.session_state.stream_results.append(res)
                st.rerun()
        with inj_c4:
            if st.button("🟠 DoH Exfil", use_container_width=True, help="Inject DNS-over-HTTPS Tunneling"):
                f = st.session_state.traffic_gen.generate_doh_tunnel()
                res = st.session_state.ai_engine.analyze_flow(f, sensitivity=anomaly_threshold)
                st.session_state.play_beep_pending = True
                st.session_state.stream_flows.append(f)
                st.session_state.stream_results.append(res)
                st.rerun()
        with inj_c5:
            if st.button("🟡 TLS Flood", use_container_width=True, help="Inject Handshake Exhaustion Flood"):
                f = st.session_state.traffic_gen.generate_tls_flood()
                res = st.session_state.ai_engine.analyze_flow(f, sensitivity=anomaly_threshold)
                st.session_state.play_beep_pending = True
                st.session_state.stream_flows.append(f)
                st.session_state.stream_results.append(res)
                st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)
    render_metric_cards(st.session_state.stream_flows, st.session_state.stream_results)
    st.markdown("<br>", unsafe_allow_html=True)

    # Telemetry Charts
    if len(st.session_state.stream_flows) > 0:
        chart_col1, chart_col2 = st.columns([2, 1])

        with chart_col1:
            st.markdown("##### 📈 Real-Time Anomaly Score Stream & Baseline Threshold")
            # Build timeline dataframe
            timeline_data = []
            for i, (f, r) in enumerate(zip(st.session_state.stream_flows, st.session_state.stream_results)):
                timeline_data.append({
                    "Flow #": i + 1,
                    "Flow ID": f["flow_id"],
                    "Anomaly Score": r["anomaly_score"],
                    "Threat": r["predicted_threat"],
                    "PCR": r["features"]["pcr"],
                    "Jitter": r["features"]["iat_jitter_coeff"],
                    "Is Anomaly": "Anomaly" if r["is_anomaly"] else "Normal"
                })
            df_tl = pd.DataFrame(timeline_data)

            fig_tl = px.scatter(
                df_tl,
                x="Flow #",
                y="Anomaly Score",
                color="Threat",
                size=[12 if s >= anomaly_threshold else 7 for s in df_tl["Anomaly Score"]],
                hover_data=["Flow ID", "PCR", "Jitter", "Is Anomaly"],
                color_discrete_map={
                    "BENIGN_WEB": "#22c55e",
                    "BENIGN_STREAMING": "#10b981",
                    "C2_BEACONING": "#ef4444",
                    "DATA_EXFILTRATION": "#dc2626",
                    "TOR_PROXY_TUNNEL": "#f97316",
                    "DOH_DATA_TUNNEL": "#eab308",
                    "TLS_DDOS_FLOOD": "#ec4899"
                },
                template="plotly_dark"
            )
            fig_tl.add_hline(
                y=anomaly_threshold,
                line_dash="dash",
                line_color="#ef4444",
                annotation_text=f"Anomaly Threshold ({anomaly_threshold})",
                annotation_position="bottom right"
            )
            fig_tl.update_layout(
                paper_bgcolor="rgba(15, 23, 42, 0.4)",
                plot_bgcolor="rgba(15, 23, 42, 0.4)",
                height=320,
                margin=dict(l=20, r=20, t=20, b=20)
            )
            st.plotly_chart(fig_tl, use_container_width=True)

        with chart_col2:
            st.markdown("##### 🥧 Threat Classification Distribution")
            threat_counts = pd.Series([r["predicted_threat"] for r in st.session_state.stream_results]).value_counts().reset_index()
            threat_counts.columns = ["Threat Category", "Count"]

            fig_pie = px.pie(
                threat_counts,
                names="Threat Category",
                values="Count",
                hole=0.45,
                color="Threat Category",
                color_discrete_map={
                    "BENIGN_WEB": "#22c55e",
                    "BENIGN_STREAMING": "#10b981",
                    "C2_BEACONING": "#ef4444",
                    "DATA_EXFILTRATION": "#dc2626",
                    "TOR_PROXY_TUNNEL": "#f97316",
                    "DOH_DATA_TUNNEL": "#eab308",
                    "TLS_DDOS_FLOOD": "#ec4899"
                },
                template="plotly_dark"
            )
            fig_pie.update_layout(
                paper_bgcolor="rgba(15, 23, 42, 0.4)",
                plot_bgcolor="rgba(15, 23, 42, 0.4)",
                height=320,
                margin=dict(l=10, r=10, t=10, b=10),
                legend=dict(orientation="h", yanchor="bottom", y=-0.2)
            )
            st.plotly_chart(fig_pie, use_container_width=True)

        # Behavioral Separation Scatter Plot (PCR vs Jitter)
        st.markdown("##### 🔬 Encrypted Flow Behavioral Fingerprint: Producer-Consumer Ratio (PCR) vs IAT Jitter")
        st.caption("Notice how distinct threats cluster naturally: Exfiltration (high PCR > +0.7), C2 Beaconing (low Jitter < 0.15), and Benign Browsing.")
        fig_scatter = px.scatter(
            df_tl,
            x="PCR",
            y="Jitter",
            color="Threat",
            hover_data=["Flow ID", "Anomaly Score"],
            color_discrete_map={
                "BENIGN_WEB": "#22c55e",
                "BENIGN_STREAMING": "#10b981",
                "C2_BEACONING": "#ef4444",
                "DATA_EXFILTRATION": "#dc2626",
                "TOR_PROXY_TUNNEL": "#f97316",
                "DOH_DATA_TUNNEL": "#eab308",
                "TLS_DDOS_FLOOD": "#ec4899"
            },
            template="plotly_dark",
            labels={
                "PCR": "Producer-Consumer Ratio (-1.0 = Pure Inbound, +1.0 = Pure Outbound)",
                "Jitter": "Inter-Arrival Time (IAT) Jitter Coefficient (Low = Rigid Periodicity)"
            }
        )
        fig_scatter.update_layout(
            paper_bgcolor="rgba(15, 23, 42, 0.4)",
            plot_bgcolor="rgba(15, 23, 42, 0.4)",
            height=300,
            margin=dict(l=20, r=20, t=20, b=20)
        )
        st.plotly_chart(fig_scatter, use_container_width=True)

        # Real-Time Alerts Feed & Active Quarantine Action Table
        st.markdown("##### 🚨 Real-Time Security Incident Stream (Most Recent 20 Flows)")
        alert_rows = []
        for i in reversed(range(len(st.session_state.stream_flows))):
            f = st.session_state.stream_flows[i]
            r = st.session_state.stream_results[i]
            threat = r["predicted_threat"]
            is_quar = st.session_state.mitigation_engine.is_quarantined(f["dst_ip"])

            alert_rows.append({
                "Index": i,
                "Flow ID": f["flow_id"],
                "Source Endpoint": f"{f['src_ip']}:{f['src_port']}",
                "Destination Target": f"{f['dst_ip']}:{f['dst_port']}",
                "SNI Domain": f.get("sni", "Unknown") or "Direct IP",
                "Anomaly Score": r["anomaly_score"],
                "Predicted Threat": threat,
                "Quarantine Status": "🛑 QUARANTINED" if is_quar else "Active",
                "Raw Flow": f,
                "Result": r
            })
            if len(alert_rows) >= 20:
                break

        # Display table with selection
        for row in alert_rows:
            f = row["Raw Flow"]
            r = row["Result"]
            threat = row["PredictedThreat"] = r["predicted_threat"]
            dst_ip = f["dst_ip"]
            is_quar = st.session_state.mitigation_engine.is_quarantined(dst_ip)
            badge_html = get_threat_badge(threat)

            with st.container():
                cols = st.columns([1.5, 2, 2.2, 1.2, 2, 1.2, 1.2])
                with cols[0]:
                    st.write(f"**{row['Flow ID']}**")
                with cols[1]:
                    st.caption(f"SRC: `{row['Source Endpoint']}`")
                with cols[2]:
                    st.write(f"`{row['Destination Target']}` ({row['SNI Domain']})")
                with cols[3]:
                    st.markdown(f"**Score:** `{r['anomaly_score']:.2f}`")
                with cols[4]:
                    st.markdown(badge_html, unsafe_allow_html=True)
                with cols[5]:
                    if st.button("Inspect", key=f"insp_{row['Index']}"):
                        st.session_state.selected_flow_detail = (f, r)
                with cols[6]:
                    if threat in ["C2_BEACONING", "DATA_EXFILTRATION", "TOR_PROXY_TUNNEL", "DOH_DATA_TUNNEL", "TLS_DDOS_FLOOD"]:
                        if is_quar:
                            if st.button("Release", key=f"rel_{row['Index']}"):
                                st.session_state.mitigation_engine.release_ip(dst_ip)
                                st.rerun()
                        else:
                            if st.button("Block IP", key=f"blk_{row['Index']}"):
                                st.session_state.mitigation_engine.quarantine_ip(
                                    ip=dst_ip,
                                    threat_type=threat,
                                    anomaly_score=r["anomaly_score"],
                                    details=f"Automated SOAR block from live feed for {row['Flow ID']}"
                                )
                                st.rerun()
                st.markdown("<hr style='margin: 4px 0px; border-color: #1e293b;'>", unsafe_allow_html=True)

    else:
        st.info("ℹ️ No encrypted flows currently in stream buffer. Click **'Stream 5 Flows'** or **'Inject C2 Beacon'** above to begin live analysis.")


# ==============================================================================
# MODULE 2: PCAP / PCAPNG FILE DEEP INSPECTION
# ==============================================================================
elif app_mode == "📁 PCAP / PCAPNG File Deep Inspection":
    st.subheader("📁 Encrypted Packet Capture (PCAP) Ingestion & Deep Forensics")
    st.caption("Upload a `.pcap` or `.pcapng` capture file to reconstruct bidirectional TLS flows, extract cryptographic JA3 fingerprints, and execute AI threat detection.")

    pcap_col1, pcap_col2 = st.columns([2, 1])
    with pcap_col1:
        uploaded_file = st.file_uploader("Upload Network Capture (.pcap / .pcapng)", type=["pcap", "pcapng"])
    with pcap_col2:
        st.markdown("##### ⚡ Benchmark Attack PCAPs")
        pcap_list = st.session_state.dataset_manager.list_pcaps()
        pcap_choices = [p["name"] for p in pcap_list] + ["sample_traffic.pcap"]
        selected_pcap_name = st.selectbox("Select Benchmark PCAP:", pcap_choices, index=0)
        
        if st.button("📥 Load & Analyze Selected PCAP", use_container_width=True):
            if selected_pcap_name == "sample_traffic.pcap":
                target_pcap_path = os.path.join(os.path.dirname(__file__), "sample_traffic.pcap")
                if not os.path.exists(target_pcap_path):
                    generate_sample_pcap(target_pcap_path)
            else:
                target_pcap_path = os.path.join(os.path.dirname(__file__), "datasets", "pcaps", selected_pcap_name)
            
            analyzer = PCAPAnalyzer()
            with st.spinner(f"Analyzing {selected_pcap_name}..."):
                flows = analyzer.analyze_pcap_file(target_pcap_path)
                results = [st.session_state.ai_engine.analyze_flow(f, sensitivity=anomaly_threshold) for f in flows]
                st.session_state.pcap_results = (flows, results)
                if any(r["is_anomaly"] for r in results):
                    st.session_state.play_beep_pending = True
                st.rerun()

    if uploaded_file is not None:
        # Save temp file and analyze
        temp_path = os.path.join(os.path.dirname(__file__), f"temp_{uploaded_file.name}")
        with open(temp_path, "wb") as f_out:
            f_out.write(uploaded_file.read())
        try:
            analyzer = PCAPAnalyzer()
            with st.spinner("Reconstructing TCP flows & extracting TLS metadata..."):
                flows = analyzer.analyze_pcap_file(temp_path)
                results = [st.session_state.ai_engine.analyze_flow(f, sensitivity=anomaly_threshold) for f in flows]
                st.session_state.pcap_results = (flows, results)
                if any(r["is_anomaly"] for r in results):
                    st.session_state.play_beep_pending = True
        except Exception as e:
            st.error(f"Error parsing PCAP file: {e}")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    # Render PCAP results if available
    if st.session_state.pcap_results:
        p_flows, p_results = st.session_state.pcap_results
        st.markdown("---")
        st.markdown(f"#### 📊 Forensics Summary: {len(p_flows)} Reconstructed Encrypted Flows")
        render_metric_cards(p_flows, p_results)
        st.markdown("<br>", unsafe_allow_html=True)

        # Flow summary table
        pcap_table_data = []
        for i, (f, r) in enumerate(zip(p_flows, p_results)):
            pcap_table_data.append({
                "#": i + 1,
                "Flow ID": f["flow_id"],
                "Source": f"{f['src_ip']}:{f['src_port']}",
                "Destination": f"{f['dst_ip']}:{f['dst_port']}",
                "SNI": f.get("sni", "N/A"),
                "Packets": f["total_packets"],
                "Bytes": f["total_bytes"],
                "PCR": r["features"]["pcr"],
                "Anomaly Score": r["anomaly_score"],
                "Predicted Threat": r["predicted_threat"],
                "Confidence": f"{r['confidence'] * 100:.1f}%"
            })
        st.dataframe(pd.DataFrame(pcap_table_data), use_container_width=True)

        st.markdown("##### 🔍 Select Flow for Deep Cryptographic & Feature Attribution Inspection")
        flow_options = [f"{i+1}: {f['flow_id']} ({f['src_ip']} -> {f['dst_ip']}) - {r['predicted_threat']}" for i, (f, r) in enumerate(zip(p_flows, p_results))]
        selected_idx = st.selectbox("Choose Flow to Inspect:", range(len(flow_options)), format_func=lambda idx: flow_options[idx])

        if selected_idx is not None:
            st.session_state.selected_flow_detail = (p_flows[selected_idx], p_results[selected_idx])


# ==============================================================================
# MODULE 3: BENCHMARK DATASETS & MODEL TRAINING LAB
# ==============================================================================
elif app_mode == "📊 Benchmark Datasets & Model Training Lab":
    st.subheader("📊 Benchmark Datasets & AI Model Training Lab")
    st.caption("Inspect standard encrypted network traffic datasets, explore feature distributions and correlations, evaluate classification performance, and retrain the AI detection models.")

    dm = st.session_state.dataset_manager
    catalog = dm.list_datasets()

    dataset_options = {
        "master_unified_eta": "Master Unified ETA Benchmark (7,000 flows)",
        "ctu13_botnet_tls": "CTU-13 Botnet TLS & C2 Dataset (3,500 flows)",
        "cira_cic_doh_tunneling": "CIRA-CIC-DoH Encrypted Tunneling Dataset (3,200 flows)",
        "iscx_tor_vpn": "ISCX Tor & VPN Obfuscation Dataset (3,000 flows)",
        "enterprise_tls_baseline": "Enterprise TLS 1.3 Clean Baseline (2,500 flows)"
    }

    ds_col1, ds_col2 = st.columns([2, 1])
    with ds_col1:
        selected_ds_key = st.selectbox(
            "Select Benchmark Dataset:",
            list(dataset_options.keys()),
            format_func=lambda k: dataset_options[k]
        )
    with ds_col2:
        st.markdown("<div style='padding-top: 28px;'></div>", unsafe_allow_html=True)
        if st.button("🔄 Reload / Refresh Datasets", use_container_width=True):
            st.session_state.dataset_manager = DatasetManager()
            st.success("Datasets refreshed.")
            st.rerun()

    meta = catalog[selected_ds_key]
    df_selected = dm.load_dataset(selected_ds_key)

    # Dataset Metadata Banner
    st.markdown(f"""
    <div style='background: rgba(15, 23, 42, 0.75); border: 1px solid #334155; border-radius: 8px; padding: 14px; margin-bottom: 16px;'>
        <div style='font-size: 1.1rem; font-weight: bold; color: #38bdf8;'>{meta['title']}</div>
        <div style='color: #cbd5e1; font-size: 0.9rem; margin-top: 4px;'>{meta['description']}</div>
        <div style='color: #94a3b8; font-size: 0.8rem; margin-top: 6px;'><b>Citation / Origin:</b> {meta['source']} | <b>File:</b> <code>{meta['filename']}</code></div>
    </div>
    """, unsafe_allow_html=True)

    # Summary KPI Cards
    total_records = len(df_selected)
    unique_classes = df_selected["label"].nunique()
    threat_records = sum(df_selected["label"] != "BENIGN_WEB") - sum(df_selected["label"] == "BENIGN_STREAMING")
    threat_pct = round((threat_records / total_records) * 100, 1)

    k1, k2, k3, k4, k5 = st.columns(5)
    with k1:
        st.markdown(f"""
        <div class='metric-box'>
            <div class='metric-title'>Dataset Records</div>
            <div class='metric-val'>{total_records:,}</div>
            <div class='metric-sub'>Flow Samples</div>
        </div>
        """, unsafe_allow_html=True)
    with k2:
        st.markdown(f"""
        <div class='metric-box'>
            <div class='metric-title'>Threat Classes</div>
            <div class='metric-val'>{unique_classes}</div>
            <div class='metric-sub'>Categorical Labels</div>
        </div>
        """, unsafe_allow_html=True)
    with k3:
        st.markdown(f"""
        <div class='metric-box'>
            <div class='metric-title'>Malicious Share</div>
            <div class='metric-val' style='color: #f97316;'>{threat_pct}%</div>
            <div class='metric-sub'>Threat Prevalence</div>
        </div>
        """, unsafe_allow_html=True)
    with k4:
        st.markdown(f"""
        <div class='metric-box'>
            <div class='metric-title'>Flow Features</div>
            <div class='metric-val'>{len(df_selected.columns) - 1}</div>
            <div class='metric-sub'>Telemetry Attributes</div>
        </div>
        """, unsafe_allow_html=True)
    with k5:
        st.markdown(f"""
        <div class='metric-box'>
            <div class='metric-title'>Storage Size</div>
            <div class='metric-val' style='color: #22c55e;'>{meta['size_mb']} MB</div>
            <div class='metric-sub'>CSV Disk Size</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Tabs for Data Exploration, Evaluation, Retraining, and Custom Upload
    d_tab1, d_tab2, d_tab3, d_tab4 = st.tabs([
        "📋 Data Explorer & Telemetry Analytics",
        "🧪 Model Evaluation Lab",
        "🚀 Retrain AI Engine on Dataset",
        "📥 Custom Dataset Ingestion"
    ])

    # -------------------------------------------------------------
    # TAB 1: Data Explorer & Telemetry Analytics
    # -------------------------------------------------------------
    with d_tab1:
        st.markdown("##### 🔍 Telemetry & Behavioral Distributions")
        t1_col1, t1_col2 = st.columns([1, 1])

        with t1_col1:
            st.markdown("###### Class Composition")
            class_counts = df_selected["label"].value_counts().reset_index()
            class_counts.columns = ["Class", "Count"]
            fig_ds_pie = px.pie(
                class_counts,
                names="Class",
                values="Count",
                hole=0.4,
                color="Class",
                color_discrete_map={
                    "BENIGN_WEB": "#22c55e",
                    "BENIGN_STREAMING": "#10b981",
                    "C2_BEACONING": "#ef4444",
                    "DATA_EXFILTRATION": "#dc2626",
                    "TOR_PROXY_TUNNEL": "#f97316",
                    "DOH_DATA_TUNNEL": "#eab308",
                    "TLS_DDOS_FLOOD": "#ec4899"
                },
                template="plotly_dark"
            )
            fig_ds_pie.update_layout(
                paper_bgcolor="rgba(15, 23, 42, 0.4)",
                plot_bgcolor="rgba(15, 23, 42, 0.4)",
                height=300,
                margin=dict(l=10, r=10, t=10, b=10)
            )
            st.plotly_chart(fig_ds_pie, use_container_width=True)

        with t1_col2:
            st.markdown("###### Feature Distribution Histogram")
            feature_to_plot = st.selectbox(
                "Select Feature to Visualize:",
                ["pcr", "iat_jitter_coeff", "beaconing_score", "pkt_len_mean", "sni_entropy", "bytes_per_sec", "total_packets"],
                index=0
            )
            fig_hist = px.histogram(
                df_selected,
                x=feature_to_plot,
                color="label",
                barmode="overlay",
                nbins=40,
                color_discrete_map={
                    "BENIGN_WEB": "#22c55e",
                    "BENIGN_STREAMING": "#10b981",
                    "C2_BEACONING": "#ef4444",
                    "DATA_EXFILTRATION": "#dc2626",
                    "TOR_PROXY_TUNNEL": "#f97316",
                    "DOH_DATA_TUNNEL": "#eab308",
                    "TLS_DDOS_FLOOD": "#ec4899"
                },
                template="plotly_dark"
            )
            fig_hist.update_layout(
                paper_bgcolor="rgba(15, 23, 42, 0.4)",
                plot_bgcolor="rgba(15, 23, 42, 0.4)",
                height=300,
                margin=dict(l=10, r=10, t=10, b=10)
            )
            st.plotly_chart(fig_hist, use_container_width=True)

        # Feature Correlation Heatmap
        st.markdown("###### 🌡️ Key Telemetry Correlation Heatmap")
        corr_cols = ["pcr", "iat_jitter_coeff", "beaconing_score", "pkt_len_mean", "sni_entropy", "bytes_per_sec", "total_packets"]
        corr_matrix = df_selected[corr_cols].corr()
        fig_corr = px.imshow(
            corr_matrix,
            text_auto=".2f",
            color_continuous_scale="RdBu_r",
            template="plotly_dark",
            aspect="auto"
        )
        fig_corr.update_layout(
            paper_bgcolor="rgba(15, 23, 42, 0.4)",
            plot_bgcolor="rgba(15, 23, 42, 0.4)",
            height=300,
            margin=dict(l=10, r=10, t=10, b=10)
        )
        st.plotly_chart(fig_corr, use_container_width=True)

        # Records Table & Export
        st.markdown("###### 📄 Dataset Records (Sample 100 Rows)")
        st.dataframe(df_selected.head(100), use_container_width=True)

        exp_c1, exp_c2, exp_c3 = st.columns([1.5, 1.5, 3])
        with exp_c1:
            csv_bytes = df_selected.to_csv(index=False).encode("utf-8")
            st.download_button(
                "📥 Export Dataset (CSV)",
                data=csv_bytes,
                file_name=meta["filename"],
                mime="text/csv",
                use_container_width=True
            )
        with exp_c2:
            json_bytes = df_selected.head(500).to_json(orient="records", indent=2).encode("utf-8")
            st.download_button(
                "📥 Export Sample (JSON)",
                data=json_bytes,
                file_name=meta["filename"].replace(".csv", "_sample.json"),
                mime="application/json",
                use_container_width=True
            )
        with exp_c3:
            if st.button("⚡ Inject 10 Random Samples to Live Stream Feed", use_container_width=True):
                sample_rows = df_selected.sample(n=10, random_state=int(time.time()))
                for _, row in sample_rows.iterrows():
                    # Construct flow dict
                    fake_now = time.time()
                    flow_record = {
                        "flow_id": f"DS-FLW-{np.random.randint(1000, 9999)}",
                        "timestamp": fake_now,
                        "src_ip": "192.168.1." + str(np.random.randint(20, 200)),
                        "src_port": np.random.randint(49152, 65535),
                        "dst_ip": "104.244.42." + str(np.random.randint(1, 250)),
                        "dst_port": 443 if row["is_suspicious_port"] == 0 else 8443,
                        "proto": "TLS 1.3",
                        "sni": "dataset-sample.internal",
                        "sni_entropy": row["sni_entropy"],
                        "ja3_hash": "a0e9f5d64349fb13191bc781f81f42e1" if row["ja3_threat_flag"] == 1.0 else "cd08e31494f9531f560d64cfa3f2233c",
                        "ja3_threat": bool(row["ja3_threat_flag"] == 1.0),
                        "packet_lengths": [int(row["pkt_len_mean"])] * int(row["total_packets"]),
                        "packet_directions": [1 if row["pcr"] > 0 else -1] * int(row["total_packets"]),
                        "packet_timestamps": [fake_now + (i * row["iat_mean_ms"] / 1000.0) for i in range(int(row["total_packets"]))],
                        "duration": row["flow_duration"],
                        "total_packets": row["total_packets"],
                        "total_bytes": row["total_bytes"],
                        "threat_label_truth": row["label"]
                    }
                    res = st.session_state.ai_engine.analyze_flow(flow_record, sensitivity=anomaly_threshold)
                    if res["is_anomaly"]:
                        st.session_state.play_beep_pending = True
                    st.session_state.stream_flows.append(flow_record)
                    st.session_state.stream_results.append(res)
                st.success("Successfully injected 10 flows into the Live Stream Buffer!")

    # -------------------------------------------------------------
    # TAB 2: Model Evaluation Lab
    # -------------------------------------------------------------
    with d_tab2:
        st.markdown("##### 🧪 Model Benchmark Performance on Selected Dataset")
        st.write("Execute the currently active AI models on this benchmark dataset to measure precision, recall, and detection accuracy.")

        if st.button("🚀 Run Model Benchmark Evaluation", use_container_width=True):
            with st.spinner("Evaluating models on dataset..."):
                eval_metrics = dm.evaluate_model(df_selected, st.session_state.ai_engine)
                st.session_state[f"eval_{selected_ds_key}"] = eval_metrics

        if f"eval_{selected_ds_key}" in st.session_state:
            res = st.session_state[f"eval_{selected_ds_key}"]
            
            ev_c1, ev_c2, ev_c3 = st.columns(3)
            with ev_c1:
                st.markdown(f"""
                <div class='metric-box'>
                    <div class='metric-title'>Overall Accuracy</div>
                    <div class='metric-val' style='color: #22c55e;'>{res['accuracy'] * 100:.2f}%</div>
                    <div class='metric-sub'>Across All Tested Flows</div>
                </div>
                """, unsafe_allow_html=True)
            with ev_c2:
                macro_f1 = res['classification_report'].get('macro avg', {}).get('f1-score', 0.0)
                st.markdown(f"""
                <div class='metric-box'>
                    <div class='metric-title'>Macro F1-Score</div>
                    <div class='metric-val' style='color: #38bdf8;'>{macro_f1 * 100:.2f}%</div>
                    <div class='metric-sub'>Balanced Class Metric</div>
                </div>
                """, unsafe_allow_html=True)
            with ev_c3:
                st.markdown(f"""
                <div class='metric-box'>
                    <div class='metric-title'>Samples Evaluated</div>
                    <div class='metric-val'>{res['total_tested']:,}</div>
                    <div class='metric-sub'>Evaluated Flow Records</div>
                </div>
                """, unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            # Confusion Matrix
            st.markdown("###### 🎯 Confusion Matrix Heatmap (True Class vs Predicted Class)")
            cm_df = pd.DataFrame(res["confusion_matrix"], index=res["classes"], columns=res["classes"])
            fig_cm = px.imshow(
                cm_df,
                text_auto=True,
                color_continuous_scale="Blues",
                labels=dict(x="Predicted Threat", y="Actual Ground Truth", color="Flows"),
                template="plotly_dark"
            )
            fig_cm.update_layout(
                paper_bgcolor="rgba(15, 23, 42, 0.4)",
                plot_bgcolor="rgba(15, 23, 42, 0.4)",
                height=380,
                margin=dict(l=10, r=10, t=10, b=10)
            )
            st.plotly_chart(fig_cm, use_container_width=True)

            # Detailed Classification Report Table
            st.markdown("###### 📊 Classification Report by Category")
            rep_rows = []
            for k, v in res["classification_report"].items():
                if isinstance(v, dict) and k not in ["macro avg", "weighted avg"]:
                    rep_rows.append({
                        "Threat Class": k,
                        "Precision": f"{v['precision'] * 100:.1f}%",
                        "Recall": f"{v['recall'] * 100:.1f}%",
                        "F1-Score": f"{v['f1-score'] * 100:.1f}%",
                        "Support (Count)": int(v["support"])
                    })
            st.dataframe(pd.DataFrame(rep_rows), use_container_width=True)

    # -------------------------------------------------------------
    # TAB 3: Retrain AI Engine on Dataset
    # -------------------------------------------------------------
    with d_tab3:
        st.markdown("##### 🚀 Model Fine-Tuning & Retraining Studio")
        st.write("Calibrate the Isolation Forest anomaly detector and Random Forest threat classifier on the selected dataset.")

        rt_c1, rt_c2, rt_c3 = st.columns(3)
        with rt_c1:
            split_ratio = st.slider("Train / Test Split Ratio", min_value=0.10, max_value=0.40, value=0.20, step=0.05, format="%.2f Test")
        with rt_c2:
            rf_trees = st.slider("Random Forest Trees", min_value=50, max_value=250, value=140, step=10)
        with rt_c3:
            rf_depth = st.slider("Max Tree Depth", min_value=8, max_value=24, value=16, step=2)

        if st.button("⚡ Retrain AI Models on Selected Dataset", use_container_width=True):
            with st.spinner("Training models and computing validation metrics on test split..."):
                retrain_res = dm.retrain_model_on_dataset(
                    dataset_df=df_selected,
                    ai_engine=st.session_state.ai_engine,
                    n_estimators=rf_trees,
                    max_depth=rf_depth,
                    test_size=split_ratio
                )
                st.session_state["latest_retrain_res"] = retrain_res
                st.success(f"Models successfully retrained! Held-out test accuracy: {retrain_res['test_accuracy'] * 100:.2f}%")

        if "latest_retrain_res" in st.session_state:
            rt_out = st.session_state["latest_retrain_res"]
            st.markdown("###### 📈 Retrained Model Validation Metrics on Held-Out Test Set")
            rc1, rc2, rc3 = st.columns(3)
            with rc1:
                st.metric("Test Accuracy", f"{rt_out['test_accuracy'] * 100:.2f}%")
            with rc2:
                st.metric("Training Samples", f"{rt_out['train_samples']:,}")
            with rc3:
                st.metric("Validation Samples", f"{rt_out['test_samples']:,}")

            # Confusion matrix
            cm_rt_df = pd.DataFrame(rt_out["confusion_matrix"], index=rt_out["classes"], columns=rt_out["classes"])
            fig_rt_cm = px.imshow(
                cm_rt_df,
                text_auto=True,
                color_continuous_scale="Greens",
                labels=dict(x="Predicted Threat", y="Actual Ground Truth", color="Count"),
                template="plotly_dark"
            )
            fig_rt_cm.update_layout(
                paper_bgcolor="rgba(15, 23, 42, 0.4)",
                plot_bgcolor="rgba(15, 23, 42, 0.4)",
                height=340,
                margin=dict(l=10, r=10, t=10, b=10)
            )
            st.plotly_chart(fig_rt_cm, use_container_width=True)

    # -------------------------------------------------------------
    # TAB 4: Custom Dataset Ingestion
    # -------------------------------------------------------------
    with d_tab4:
        st.markdown("##### 📥 Ingest Custom CSV Threat Dataset")
        st.write("Upload your own custom network flow dataset. The system will validate feature headers, visualize samples, and allow model evaluation or retraining.")

        custom_file = st.file_uploader("Upload CSV Dataset (.csv)", type=["csv"], key="custom_dataset_uploader")
        if custom_file is not None:
            try:
                custom_df = pd.read_csv(custom_file)
                st.success(f"Loaded CSV with {len(custom_df)} rows and {len(custom_df.columns)} columns.")
                
                # Check for required feature columns
                from core.feature_extractor import FEATURE_NAMES
                missing_cols = [c for c in FEATURE_NAMES if c not in custom_df.columns]
                
                if missing_cols:
                    st.warning(f"⚠️ Note: {len(missing_cols)} standard feature columns are missing: {missing_cols[:5]}... Synthesizing default values for missing columns.")
                    for col in missing_cols:
                        custom_df[col] = 0.0

                if "label" not in custom_df.columns:
                    st.info("ℹ️ No 'label' column found. Defaulting target labels to 'ANOMALOUS_UNKNOWN' for evaluation.")
                    custom_df["label"] = "ANOMALOUS_UNKNOWN"

                st.markdown("###### Preview of Uploaded Dataset")
                st.dataframe(custom_df.head(20), use_container_width=True)

                eval_btn, retrain_btn = st.columns(2)
                with eval_btn:
                    if st.button("🧪 Evaluate AI Engine on Custom Dataset", use_container_width=True):
                        custom_eval = dm.evaluate_model(custom_df, st.session_state.ai_engine)
                        st.write(f"Accuracy: **{custom_eval['accuracy'] * 100:.2f}%**")
                        st.dataframe(pd.DataFrame(custom_eval["classification_report"]).T)
                with retrain_btn:
                    if st.button("🚀 Retrain AI Engine on Custom Dataset", use_container_width=True):
                        with st.spinner("Retraining on custom dataset..."):
                            c_retrain = dm.retrain_model_on_dataset(custom_df, st.session_state.ai_engine)
                            st.success(f"Retrained on custom dataset! Test accuracy: {c_retrain['test_accuracy'] * 100:.2f}%")

            except Exception as e:
                st.error(f"Error parsing custom CSV: {e}")


# ==============================================================================
# MODULE 4: THREAT SIMULATOR & ATTACK SANDBOX
# ==============================================================================
elif app_mode == "🧪 Threat Simulator & Attack Sandbox":
    st.subheader("🧪 Interactive Encrypted Threat Simulator & Parameter Tuning")
    st.caption("Adjust behavioral and cryptographic parameters to observe how the dual-stage AI model evaluates encrypted network sessions.")

    sim_c1, sim_c2 = st.columns(2)
    with sim_c1:
        st.markdown("##### ⏱️ Timing & Packet Statistics")
        sim_duration = st.slider("Session Duration (seconds)", min_value=1.0, max_value=180.0, value=25.0, step=1.0)
        sim_packets = st.slider("Total Packet Count", min_value=6, max_value=1000, value=40, step=2)
        sim_fwd_ratio = st.slider("Forward / Outbound Ratio (1.0 = Pure Upload, 0.0 = Pure Download)", min_value=0.05, max_value=0.98, value=0.50, step=0.05)
        sim_mean_size = st.slider("Mean Packet Length (Bytes)", min_value=60, max_value=1460, value=450, step=10)
        sim_jitter = st.slider("Inter-Arrival Time (IAT) Jitter Coefficient (Low = Periodic C2 Heartbeat)", min_value=0.01, max_value=1.80, value=0.80, step=0.02)

    with sim_c2:
        st.markdown("##### 🔐 Cryptographic & Domain Attributes")
        sim_dst_port = st.selectbox("Destination Port", [443, 8443, 9001, 853, 4444, 1337], index=0)
        sim_sni = st.text_input("Server Name Indication (SNI) Domain", value="cdn-cloud-storage.aws.com")
        sim_ja3 = st.selectbox(
            "TLS JA3 Client Fingerprint",
            [
                "cd08e31494f9531f560d64cfa3f2233c (Standard Chrome 120+)",
                "b38455a272046096e6a1aa94ec4392e2 (Mozilla Firefox)",
                "a0e9f5d64349fb13191bc781f81f42e1 (Cobalt Strike C2 Beacon)",
                "72a589da586844d7f0818ce684948eea (Sliver C2 Implant)",
                "e7d705a3286e19ea42f587b344ee6865 (Metasploit Meterpreter Reverse HTTPS)",
                "406c117e6992d95188f1ae6a8ff4a0a5 (Tor Onion Browser)",
                "51c64c77e60f3980eea90869b68c58a8 (TrickBot Data Exfiltration)"
            ]
        )
        selected_ja3_hash = sim_ja3.split(" ")[0]
        ja3_lookup = lookup_ja3(selected_ja3_hash)
        is_ja3_malicious = ja3_lookup["risk_level"] in ["CRITICAL", "HIGH"] if ja3_lookup else False

    # Synthesize simulated flow
    now = time.time()
    fwd_count = int(sim_packets * sim_fwd_ratio)
    bwd_count = sim_packets - fwd_count
    sim_directions = [1] * fwd_count + [-1] * bwd_count
    np.random.shuffle(sim_directions)
    
    sim_lengths = [int(np.clip(np.random.normal(sim_mean_size, sim_mean_size * 0.3), 66, 1460)) for _ in range(sim_packets)]
    
    # Generate timestamps based on jitter
    base_step = sim_duration / max(sim_packets, 1)
    timestamps = [now]
    for _ in range(1, sim_packets):
        step = max(base_step + np.random.normal(0, base_step * sim_jitter), 0.001)
        timestamps.append(timestamps[-1] + step)

    sni_analysis = analyze_sni(sim_sni)

    simulated_flow = {
        "flow_id": "SIM-TEST-001",
        "timestamp": now,
        "src_ip": "192.168.1.100",
        "src_port": 54321,
        "dst_ip": "203.0.113.88",
        "dst_port": sim_dst_port,
        "proto": "TLS 1.3",
        "sni": sim_sni,
        "sni_entropy": sni_analysis["entropy"],
        "ja3_hash": selected_ja3_hash,
        "ja3_threat": is_ja3_malicious,
        "packet_lengths": sim_lengths,
        "packet_directions": sim_directions,
        "packet_timestamps": timestamps,
        "duration": sim_duration,
        "total_packets": sim_packets,
        "total_bytes": sum(sim_lengths)
    }

    sim_result = st.session_state.ai_engine.analyze_flow(simulated_flow, sensitivity=anomaly_threshold)
    if sim_result["is_anomaly"] and st.session_state.get("audio_alerts_enabled", True):
        play_anomaly_beep()

    st.markdown("---")
    st.markdown("##### 🎯 AI Evaluation & Real-Time Verdict")
    v_col1, v_col2, v_col3 = st.columns([1.5, 1.5, 3])
    with v_col1:
        st.markdown(f"**Threat Classification:**<br>{get_threat_badge(sim_result['predicted_threat'])}", unsafe_allow_html=True)
        st.write(f"Confidence: **{sim_result['confidence'] * 100:.1f}%**")
    with v_col2:
        score_val = sim_result['anomaly_score']
        score_color = "#ef4444" if score_val >= anomaly_threshold else "#22c55e"
        st.markdown(f"**Anomaly Score:**<br><span style='font-size: 1.8rem; font-weight: bold; color: {score_color};'>{score_val:.3f}</span>", unsafe_allow_html=True)
        st.write(f"Decision: **{'🚨 ANOMALY' if sim_result['is_anomaly'] else '✓ NORMAL'}**")
    with v_col3:
        st.markdown("**Explainable AI (XAI) Attribution Breakdown:**")
        for xai in sim_result["xai_explanation"]:
            st.markdown(f"- **{xai['factor']}**: {xai['evidence']} (*{xai['impact']}*)")

    st.session_state.selected_flow_detail = (simulated_flow, sim_result)


# ==============================================================================
# MODULE 4: ACTIVE QUARANTINE & SOAR RULES
# ==============================================================================
elif app_mode == "🛡️ Active Quarantine & SOAR Rules":
    st.subheader("🛡️ Automated Mitigation, SOAR Rules & IP Quarantine Management")
    st.caption("Review active perimeter defense actions, generated host-based firewall commands, and SOC incident records.")

    quar_list = st.session_state.mitigation_engine.quarantined_ips
    if len(quar_list) == 0:
        st.info("ℹ️ No IP addresses currently quarantined. When an attack is detected in the Live Feed or PCAP forensics, click **'Block IP'** to isolate it.")
    else:
        st.markdown(f"#### 🛑 Active Quarantined IP Addresses ({len(quar_list)})")
        for ip, entry in list(quar_list.items()):
            with st.expander(f"🔴 Blocked Target: {ip} - {entry['threat_type']} (Severity: {entry['severity']})", expanded=True):
                q_c1, q_c2 = st.columns([2, 1])
                with q_c1:
                    st.write(f"**Timestamp:** {entry['timestamp']}")
                    st.write(f"**Reason / Details:** {entry['details']}")
                    st.write(f"**Anomaly Score:** `{entry['anomaly_score']}`")
                    
                    st.markdown("###### 🛡️ Generated Windows Firewall Command (`netsh`):")
                    st.code(entry["firewall_rules"]["windows_netsh"], language="powershell")

                    st.markdown("###### 🛡️ Generated Linux `iptables` Command:")
                    st.code(entry["firewall_rules"]["linux_iptables"], language="bash")

                with q_c2:
                    st.markdown("###### Action Console")
                    if st.button(f"🔓 Release Quarantine for {ip}", key=f"unq_{ip}"):
                        st.session_state.mitigation_engine.release_ip(ip)
                        st.success(f"Released {ip} from quarantine.")
                        st.rerun()

    # Manual Quarantine Tool
    st.markdown("---")
    st.markdown("##### ➕ Manual IP Quarantine Injection")
    mq_c1, mq_c2, mq_c3 = st.columns([2, 2, 1])
    with mq_c1:
        manual_ip = st.text_input("IP Address to Block", value="198.51.100.42")
    with mq_c2:
        manual_threat = st.selectbox("Threat Category", ["C2_BEACONING", "DATA_EXFILTRATION", "TOR_PROXY_TUNNEL", "DOH_DATA_TUNNEL", "TLS_DDOS_FLOOD"])
    with mq_c3:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("Apply Block Rule", use_container_width=True):
            st.session_state.mitigation_engine.quarantine_ip(
                ip=manual_ip,
                threat_type=manual_threat,
                anomaly_score=0.95,
                details="Manually quarantined by SOC Security Analyst"
            )
            st.success(f"Quarantined {manual_ip} successfully.")
            st.rerun()


# ==============================================================================
# MODULE 5: MITRE ATT&CK MATRIX & THREAT INTEL
# ==============================================================================
elif app_mode == "📚 MITRE ATT&CK Matrix & Threat Intel":
    st.subheader("📚 MITRE ATT&CK Matrix for Encrypted Network Channels")
    st.caption("Standardized mapping of encrypted network traffic threats to the MITRE ATT&CK Enterprise Framework.")

    mitre_data = []
    for threat, info in MITRE_MAPPING.items():
        mitre_data.append({
            "Threat Category": threat,
            "Severity": info["severity"],
            "Tactic": info["tactic"],
            "Technique ID": info["technique_id"],
            "Technique Name": info["technique_name"],
            "Sub-Technique": info["sub_technique"],
            "Recommended SOAR Response": info["recommended_action"]
        })
    df_mitre = pd.DataFrame(mitre_data)
    st.dataframe(df_mitre, use_container_width=True)

    st.markdown("---")
    st.markdown("##### 📖 Encrypted Traffic Analysis (ETA) Technical Architecture")
    st.markdown("""
    - **Producer-Consumer Ratio (PCR)**: Computes the asymmetry of bidirectional data flow:
      $$\\text{PCR} = \\frac{\\text{Bytes}_{\\text{fwd}} - \\text{Bytes}_{\\text{bwd}}}{\\text{Bytes}_{\\text{fwd}} + \\text{Bytes}_{\\text{bwd}}} \\in [-1.0, 1.0]$$
      * \\(+0.75\\) to \\(+0.98\\): Strong indicator of **Encrypted Data Exfiltration** or C2 upload.
      * \\(-0.75\\) to \\(-0.95\\): Normal web browsing / video streaming downloads.
    - **Inter-Arrival Jitter Coefficient**: Coefficient of variation $\\sigma / \\mu$ across consecutive packet arrivals.
      * Regular human browsing exhibits high jitter ($> 0.6$).
      * Automated C2 beacons (Cobalt Strike, Sliver) exhibit ultra-low jitter ($< 0.15$) and rigid periodicity.
    - **JA3 Fingerprinting**: Cryptographic fingerprint generated via MD5 of ClientHello parameters:
      $$\\text{JA3} = \\text{MD5}(\\text{SSLVersion},\\text{Ciphers},\\text{Extensions},\\text{EllipticCurves},\\text{ECPointFormats})$$
    """)


# ==============================================================================
# DEEP FLOW INSPECTION MODAL / DRAWER (Shared Across Modules)
# ==============================================================================
if st.session_state.selected_flow_detail is not None:
    flow_detail, res_detail = st.session_state.selected_flow_detail
    st.markdown("---")
    st.markdown(f"### 🔬 Deep Flow Forensic Inspector: `{flow_detail['flow_id']}`")
    
    close_c1, close_c2 = st.columns([5, 1])
    with close_c2:
        if st.button("✖ Close Inspector"):
            st.session_state.selected_flow_detail = None
            st.rerun()

    fi_c1, fi_c2, fi_c3 = st.columns([1.5, 1.5, 2])
    with fi_c1:
        st.markdown("##### 🌐 Network 5-Tuple")
        st.write(f"• **Source:** `{flow_detail['src_ip']}:{flow_detail['src_port']}`")
        st.write(f"• **Destination:** `{flow_detail['dst_ip']}:{flow_detail['dst_port']}`")
        st.write(f"• **Protocol:** `{flow_detail.get('proto', 'TLS 1.3')}`")
        st.write(f"• **Duration:** `{flow_detail['duration']:.2f}s`")
        st.write(f"• **Total Packets:** `{flow_detail['total_packets']}`")
        st.write(f"• **Total Volume:** `{flow_detail['total_bytes'] / 1024:.2f} KB`")

    with fi_c2:
        st.markdown("##### 🔐 Cryptographic TLS Details")
        st.write(f"• **SNI Domain:** `{flow_detail.get('sni', 'None')}`")
        st.write(f"• **SNI Entropy:** `{flow_detail.get('sni_entropy', 0.0):.2f} bits`")
        ja3_val = flow_detail.get("ja3_hash", "N/A")
        st.write(f"• **JA3 Hash:** `{ja3_val}`")
        ja3_meta = lookup_ja3(ja3_val)
        if ja3_meta:
            st.info(f"**JA3 Signature Match:** {ja3_meta['client']}\n*{ja3_meta['description']}*")
        else:
            st.caption("JA3 Hash not in known threat registry (Generic/Dynamic client)")

    with fi_c3:
        st.markdown("##### 🧠 AI Detection Breakdown")
        st.markdown(f"Threat Verdict: {get_threat_badge(res_detail['predicted_threat'])}", unsafe_allow_html=True)
        st.write(f"Confidence: **{res_detail['confidence'] * 100:.1f}%**")
        st.write(f"Anomaly Score: **{res_detail['anomaly_score']:.3f}** (Threshold: {anomaly_threshold})")
        st.markdown("**Key Attribution Evidence:**")
        for x in res_detail["xai_explanation"]:
            st.write(f"• **{x['factor']}**: {x['evidence']}")

    # Packet Length Sequence Chart (SPLT)
    if "packet_lengths" in flow_detail and len(flow_detail["packet_lengths"]) > 0:
        st.markdown("##### 📊 Sequence of Packet Lengths and Times (SPLT)")
        pkt_df = pd.DataFrame({
            "Packet #": list(range(1, len(flow_detail["packet_lengths"]) + 1)),
            "Length (Bytes)": flow_detail["packet_lengths"],
            "Direction": ["Outbound (Client -> Server)" if d > 0 else "Inbound (Server -> Client)" for d in flow_detail["packet_directions"]]
        })
        fig_splt = px.bar(
            pkt_df,
            x="Packet #",
            y="Length (Bytes)",
            color="Direction",
            color_discrete_map={
                "Outbound (Client -> Server)": "#ef4444",
                "Inbound (Server -> Client)": "#38bdf8"
            },
            template="plotly_dark"
        )
        fig_splt.update_layout(
            paper_bgcolor="rgba(15, 23, 42, 0.4)",
            plot_bgcolor="rgba(15, 23, 42, 0.4)",
            height=260,
            margin=dict(l=20, r=20, t=20, b=20)
        )
        st.plotly_chart(fig_splt, use_container_width=True)

    # Automated Mitigation Action Box
    st.markdown("##### 🛡️ One-Click Isolation & Firewall Rule Generation")
    fw_cmds = st.session_state.mitigation_engine.generate_firewall_commands(
        src_ip=flow_detail["src_ip"],
        dst_ip=flow_detail["dst_ip"],
        dst_port=flow_detail["dst_port"],
        threat_type=res_detail["predicted_threat"]
    )
    st.code(fw_cmds["windows_netsh"], language="powershell")
