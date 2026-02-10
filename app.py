import streamlit as st
import dns.resolver
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed

# -------------------------
# Page Setup
# -------------------------
st.set_page_config(page_title="Domain Security Dashboard", layout="wide")
st.title("Domain Security & Reputation Dashboard")

uploaded_file = st.file_uploader("Upload TXT file with domains (one per line)", type=["txt"])

resolver = dns.resolver.Resolver()
resolver.nameservers = ['8.8.8.8', '1.1.1.1']

progress_bar = st.progress(0)
status_text = st.empty()

# -------------------------
# DNS Check Functions
# -------------------------
def get_spf(domain):
    try:
        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = "".join([part.decode() for part in rdata.strings])
            if txt.lower().startswith("v=spf1"):
                return txt
    except:
        return None
    return None

def get_dmarc(domain):
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt = "".join([part.decode() for part in rdata.strings])
            if txt.lower().startswith("v=dmarc"):
                return txt
    except:
        return None
    return None

# -------------------------
# Security Score Calculation
# -------------------------
def calculate_security_score(dmarc, spf, plusall, qmark):
    score = 0
    if dmarc == "Yes":
        score += 40
    if spf == "Yes":
        score += 30
    if plusall == "Yes":
        score -= 20
    if qmark == "Yes":
        score -= 10
    return max(0, min(score, 100))

def process_domain(domain):
    spf = get_spf(domain)
    dmarc = get_dmarc(domain)
    spf_plus = "Yes" if spf and "+all" in spf.lower() else "No"
    spf_qmark = "Yes" if spf and "?all" in spf.lower() else "No"
    score = calculate_security_score("Yes" if dmarc else "No",
                                     "Yes" if spf else "No",
                                     spf_plus,
                                     spf_qmark)
    return {
        "Domain": domain,
        "DMARC": "Yes" if dmarc else "No",
        "SPF": "Yes" if spf else "No",
        "SPF +all": spf_plus,
        "SPF ?all": spf_qmark,
        "Security Score": score,
        "MXToolbox": f'https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{domain}',
        "Talos": f'https://talosintelligence.com/reputation_center/lookup?search={domain}',
    }

# -------------------------
# Modern dark table renderer
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
    domains = uploaded_file.read().decode("utf-8").splitlines()
    domains = [d.strip().lower() for d in domains if d.strip()]

    results = []
    total = len(domains)

    with st.spinner("Checking domains..."):
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(process_domain, d): d for d in domains}
            for i, future in enumerate(as_completed(futures)):
                results.append(future.result())
                progress_bar.progress((i + 1) / total)
                status_text.text(f"Processing {i + 1}/{total} domains...")

    df = pd.DataFrame(results)

    # -------------------------
    # Sidebar Filters + Sorting
    # -------------------------
    st.sidebar.header("Filters")
    dmarc_filter = st.sidebar.selectbox("DMARC", ["All", "Yes", "No"])
    spf_filter = st.sidebar.selectbox("SPF", ["All", "Yes", "No"])
    plusall_filter = st.sidebar.selectbox("SPF +all", ["All", "Yes", "No"])
    qmark_filter = st.sidebar.selectbox("SPF ?all", ["All", "Yes", "No"])
    min_score = st.sidebar.slider("Minimum Security Score", 0, 100, 0)

    sort_column = st.sidebar.selectbox("Sort by column", df.columns.tolist(), index=df.columns.get_loc("Security Score"))
    sort_ascending = st.sidebar.checkbox("Ascending order?", value=False)

    if dmarc_filter != "All":
        df = df[df["DMARC"] == dmarc_filter]
    if spf_filter != "All":
        df = df[df["SPF"] == spf_filter]
    if plusall_filter != "All":
        df = df[df["SPF +all"] == plusall_filter]
    if qmark_filter != "All":
        df = df[df["SPF ?all"] == qmark_filter]
    df = df[df["Security Score"] >= min_score]

    df = df.sort_values(by=sort_column, ascending=sort_ascending)

    # -------------------------
    # Render modern table
    # -------------------------
    st.subheader("Domain Results")
    st.markdown(render_modern_table(df), unsafe_allow_html=True)

    # -------------------------
    # Download CSV
    # -------------------------
    st.download_button(
        "Download results as CSV",
        df.drop(columns=["MXToolbox", "Talos"]).to_csv(index=False),
        "domain_results.csv",
        "text/csv"
    )
