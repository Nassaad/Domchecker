import streamlit as st
import dns.resolver
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import time

# -------------------------
# Page Setup
# -------------------------
st.set_page_config(page_title="Domain Security Dashboard", layout="wide")
st.title("Domain Security & Reputation Dashboard")

uploaded_file = st.file_uploader("Upload TXT file with domains (one per line)", type=["txt"])

resolver = dns.resolver.Resolver()
resolver.nameservers = ['8.8.8.8', '1.1.1.1']

# -------------------------
# VirusTotal API
# -------------------------
VT_API_KEY = "dd460254e98cb6dd28bcb50bd291b81fbc9ac5fab0949abd169fd48b8ca1d891"
VT_HEADERS = {"x-apikey": VT_API_KEY}

# -------------------------
# Read uploaded file (cached)
# -------------------------
@st.cache_data
def read_domains(uploaded_file):
    content = uploaded_file.read().decode("utf-8").splitlines()
    domains = [d.strip().lower() for d in content if d.strip()]
    return domains

# -------------------------
# DNS Check Functions
# -------------------------
def get_spf(domain):
    try:
        answers = resolver.resolve(domain, "TXT", lifetime=5)
        for rdata in answers:
            txt = "".join([part.decode() for part in rdata.strings])
            if txt.lower().startswith("v=spf1"):
                return txt
    except:
        return None
    return None

def get_dmarc(domain):
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        for rdata in answers:
            txt = "".join([part.decode() for part in rdata.strings])
            if txt.lower().startswith("v=dmarc"):
                return txt
    except:
        return None
    return None

# -------------------------
# VirusTotal check with caching
# -------------------------
vt_cache = {}

def check_virustotal(domain):
    if domain in vt_cache:
        return vt_cache[domain]
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        resp = requests.get(url, headers=VT_HEADERS, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            blacklist = "Yes" if stats.get("malicious", 0) > 0 else "No"
        else:
            blacklist = "Unknown"
    except Exception:
        blacklist = "Unknown"
    vt_cache[domain] = blacklist
    return blacklist

# -------------------------
# Process DNS only (fast)
# -------------------------
def process_dns_only(domain):
    spf = get_spf(domain)
    dmarc = get_dmarc(domain)
    spf_plus = "Yes" if spf and "+all" in spf.lower() else "No"
    spf_qmark = "Yes" if spf and "?all" in spf.lower() else "No"
    return {
        "Domain": domain,
        "DMARC": "Yes" if dmarc else "No",
        "SPF": "Yes" if spf else "No",
        "SPF +all": spf_plus,
        "SPF ?all": spf_qmark,
        "MXToolbox": f'https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{domain}',
        "Talos": f'https://talosintelligence.com/reputation_center/lookup?search={domain}',
    }

# -------------------------
# Render modern dark table
# -------------------------
def render_modern_table(df):
    html = """
    <div style="overflow-x:auto; max-height:600px; border-radius:8px; box-shadow: 0 4px 8px rgba(0,0,0,0.3);">
    <table style="border-collapse: collapse; width:100%; font-family: Arial, sans-serif; border-radius:8px; overflow:hidden;">
    <thead style="position: sticky; top: 0; background-color:#121212; color:white; z-index:1;">
    <tr>
    """
    for col in df.columns:
        html += f'<th style="padding:10px; text-align:center; color:white">{col}</th>'
    html += "</tr></thead><tbody>"

    for _, (_, row) in enumerate(df.iterrows()):
        html += f'<tr style="background-color:#1e1e1e; color:white; transition: all 0.2s;">'
        for col in df.columns:
            if col in ["MXToolbox", "Talos"]:
                html += f'<td style="text-align:center; padding:8px;"><a href="{row[col]}" target="_blank" style="color:#4fc3f7; text-decoration:none;">Open</a></td>'
            else:
                html += f'<td style="text-align:center; padding:8px; color:white">{row[col]}</td>'
        html += "</tr>"
    html += """
    </tbody></table>
    <style>
    table tr:hover {background-color: #333333;}
    table th {border-bottom: 2px solid #444444;}
    table td, table th {border-right: 1px solid #2c2c2c;}
    table td:last-child, table th:last-child {border-right: none;}
    </style>
    </div>
    """
    return html

# -------------------------
# Main App Logic
# -------------------------
if uploaded_file:
    domains = read_domains(uploaded_file)

    # -------------------------
    # Step 1: DNS Checks (fast & parallel)
    # -------------------------
    if "df_dns" not in st.session_state:
        progress_bar = st.progress(0)
        status_text = st.empty()
        dns_results = []

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(process_dns_only, d): d for d in domains}
            for i, future in enumerate(as_completed(futures)):
                dns_results.append(future.result())
                progress_bar.progress((i + 1)/len(domains))
                status_text.text(f"Processing DNS {i + 1}/{len(domains)}")

        st.session_state.df_dns = pd.DataFrame(dns_results)

    df = st.session_state.df_dns.copy()

    # -------------------------
    # Step 2: VirusTotal Blacklist (rate-limited, progressive)
    # -------------------------
    if "df_blacklist" not in st.session_state:
        blacklist_list = []
        progress_bar = st.progress(0)
        status_text = st.empty()
        for i, domain in enumerate(df["Domain"]):
            blacklist_list.append(check_virustotal(domain))
            progress_bar.progress((i + 1)/len(df))
            status_text.text(f"Checking VirusTotal {i + 1}/{len(df)}")
            time.sleep(1)  # VT rate-limit, adjust for your tier
        df["Blacklist"] = blacklist_list
        st.session_state.df_blacklist = df
    else:
        df = st.session_state.df_blacklist.copy()

    # -------------------------
    # Sidebar Filters + Sorting
    # -------------------------
    st.sidebar.header("Filters")
    dmarc_filter = st.sidebar.selectbox("DMARC", ["All", "Yes", "No"])
    spf_filter = st.sidebar.selectbox("SPF", ["All", "Yes", "No"])
    plusall_filter = st.sidebar.selectbox("SPF +all", ["All", "Yes", "No"])
    qmark_filter = st.sidebar.selectbox("SPF ?all", ["All", "Yes", "No"])
    blacklist_filter = st.sidebar.selectbox("Blacklist", ["All", "Yes", "No"])

    sortable_columns = [col for col in df.columns if col not in ["MXToolbox", "Talos"]]
    sort_column = st.sidebar.selectbox("Sort by column", sortable_columns, index=sortable_columns.index("Domain"))
    sort_ascending = st.sidebar.checkbox("Ascending order?", value=True)

    # Apply filters
    if dmarc_filter != "All":
        df = df[df["DMARC"] == dmarc_filter]
    if spf_filter != "All":
        df = df[df["SPF"] == spf_filter]
    if plusall_filter != "All":
        df = df[df["SPF +all"] == plusall_filter]
    if qmark_filter != "All":
        df = df[df["SPF ?all"] == qmark_filter]
    if blacklist_filter != "All":
        df = df[df["Blacklist"] == blacklist_filter]

    # Apply sorting
    df = df.sort_values(by=sort_column, ascending=sort_ascending)

    # -------------------------
    # Render Table
    # -------------------------
    st.subheader("Domain Results")
    st.markdown(render_modern_table(df), unsafe_allow_html=True)

    # -------------------------
    # CSV Download
    # -------------------------
    st.download_button(
        "Download results as CSV",
        df.drop(columns=["MXToolbox", "Talos"]).to_csv(index=False),
        "domain_results.csv",
        "text/csv"
    )
