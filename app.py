import streamlit as st
import plotly.graph_objects as go
from core_engine import full_scan
import os
import time

st.set_page_config(page_title="SafeNet BD | Phishing Shield", page_icon="🛡️", layout="wide")

# --- Custom Premium CSS ---
st.markdown("""
    <style>
    .main {background-color: #0b0f19;}
    h1, h2, h3 {color: #00e5ff;}
    .metric-box {
        background-color: #1c2331; padding: 20px; border-radius: 10px; 
        border-left: 4px solid #00e5ff; text-align: center;
    }
    .metric-title {color: #a0aec0; font-size: 14px; text-transform: uppercase;}
    .metric-value {color: #ffffff; font-size: 24px; font-weight: bold;}
    .stTextInput>div>div>input {
        background-color: #1c2331; color: #fff; border: 1px solid #00e5ff; border-radius: 8px;
    }
    </style>
""", unsafe_allow_html=True)

# --- Header ---
st.title("🛡️ SafeNet BD: AI Phishing Shield")
st.markdown("Enter a suspicious URL (e.g., bKash offers, Job circulars) to instantly analyze its threat level using WHOIS logic and Gemini AI.")

# --- API Key Check ---
if not os.getenv("GEMINI_API_KEY"):
    st.warning("⚠️ GEMINI_API_KEY is not set in `.env`. AI Analysis will be offline.")

# --- Input Section ---
col1, col2 = st.columns([4, 1])
with col1:
    url_input = st.text_input("🔗 Target URL:", placeholder="https://free-bkash-offer-2026.com", label_visibility="collapsed")
with col2:
    scan_btn = st.button("🔍 Deep Scan", type="primary", use_container_width=True)

# --- Scan Logic ---
if scan_btn and url_input:
    with st.spinner("Initiating Cyber-Scan... Mapping Domain... Querying AI..."):
        time.sleep(0.5)
        results = full_scan(url_input)
        
        ai_res = results.get("ai_analysis", {})
        score = ai_res.get("risk_score", 0)
        verdict = ai_res.get("verdict", "Unknown")
        reasoning = ai_res.get("reasoning_bengali", "No reasoning provided.")
        
        # Color coding
        if score < 30:
            color = "#00FF00"  # Safe
        elif score < 70:
            color = "#FFA500"  # Suspicious
        else:
            color = "#FF0000"  # Danger
            
        st.markdown("---")
        
        # --- UI Layout ---
        res_col1, res_col2 = st.columns([1, 2])
        
        with res_col1:
            st.subheader("📊 Threat Level")
            # Gauge Chart
            fig = go.Figure(go.Indicator(
                mode = "gauge+number",
                value = score,
                domain = {'x': [0, 1], 'y': [0, 1]},
                title = {'text': verdict, 'font': {'color': color, 'size': 24}},
                gauge = {
                    'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "white"},
                    'bar': {'color': color},
                    'bgcolor': "#1c2331",
                    'steps': [
                        {'range': [0, 30], 'color': "rgba(0, 255, 0, 0.1)"},
                        {'range': [30, 70], 'color': "rgba(255, 165, 0, 0.1)"},
                        {'range': [70, 100], 'color': "rgba(255, 0, 0, 0.1)"}
                    ]
                }
            ))
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font={'color': "white"}, margin=dict(l=20, r=20, t=50, b=20), height=300)
            st.plotly_chart(fig, use_container_width=True)
            
        with res_col2:
            st.subheader("🧠 AI Security Analyst Report")
            st.info(reasoning)
            
            st.markdown("### 🔎 Deep Inspection Metrics")
            
            # Row 1: Deterministic URL/WHOIS Metrics
            d_col1, d_col2, d_col3 = st.columns(3)
            with d_col1:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-title">Domain Age</div>
                    <div class="metric-value">{results['whois_features'].get('domain_age_days', 'N/A')} Days</div>
                </div>
                """, unsafe_allow_html=True)
            with d_col2:
                ssl_text = "🔒 Secure" if results['ssl_details']['valid'] else "🔓 Unsafe"
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-title">SSL Protocol</div>
                    <div class="metric-value">{ssl_text}</div>
                </div>
                """, unsafe_allow_html=True)
            with d_col3:
                susp = len(results['url_features']['suspicious_words'])
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-title">Suspicious Keywords</div>
                    <div class="metric-value">{susp} Found</div>
                </div>
                """, unsafe_allow_html=True)
                
            st.write("") # Spacer
            
            # Row 2: Premium Extracted Data (SSL Issuer, Final URL, Title)
            p_col1, p_col2 = st.columns(2)
            with p_col1:
                final_url = results['url_features']['final_url']
                is_redirected = results['url_features']['original_url'] != final_url
                redir_text = f"🔀 Redirected to: {final_url[:30]}..." if is_redirected else "✅ Direct Link"
                
                st.markdown(f"""
                <div class="metric-box" style="text-align: left; border-left-color: {'#FF0000' if is_redirected else '#00e5ff'};">
                    <div class="metric-title">Redirect Unmasking</div>
                    <div style="color: #fff; font-size: 14px; margin-top: 5px;">{redir_text}</div>
                </div>
                """, unsafe_allow_html=True)
                
            with p_col2:
                issuer = results['ssl_details'].get('issuer', 'Unknown')
                st.markdown(f"""
                <div class="metric-box" style="text-align: left;">
                    <div class="metric-title">SSL Certificate Issuer</div>
                    <div style="color: #fff; font-size: 14px; margin-top: 5px;">{issuer}</div>
                </div>
                """, unsafe_allow_html=True)
                
            st.write("")
            st.markdown(f"""
            <div class="metric-box" style="text-align: left; padding: 15px;">
                <div class="metric-title">Scraped DOM Target Title</div>
                <div style="color: #fff; font-size: 15px; margin-top: 5px; font-weight: bold;">{results['dom_context']['page_title']}</div>
            </div>
            """, unsafe_allow_html=True)
