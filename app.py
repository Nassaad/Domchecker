import streamlit as st
import dns.resolver
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed

st.set_page_config(page_title="Domain Security Checker", layout="wide")
st.title("Domain Security & Reputation Checker (Cloud-Friendly)")

uploaded_file = st.file_uploader("Upload TXT file with domains (one per line)", type=["txt"])

resolver = dns.resolver.Resolver()
resolver.nameservers = ['8.8.8.8', '1.1.1.1']

progress_bar = st.progress(0)
status_text = st.empty()

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
        "MXToolbox": f'<a href="https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{domain}" target="_blank">Open</a>',
        "Talos": f'<a href="https://talosintelligence.com/reputation_center/lookup?search={domain}" target="_blank">Open</a>',
    }

def color_cell(value, positive="Yes"):
    """Soft pastel colors for Yes/No."""
    if value == positive:
        color = "#c8e6c9"  # light green
    else:
        color = "#ffcdd2"  # light red
    return f'<td style="background-color:{color}; text-align:center">{value}</td>'

def color_score(value):
    """Pastel colors based on security score."""
    if value > 70:
        color = "#c8e6c9"  # green
    elif value >= 40:
        color = "#fff9c4"  # yellow
    else:
        color = "#ffcdd2"  # red
    return f'<td style="background-color:{color}; text-align:center">{value}</td>'

def render_color_table(df):
    html = '<table border="1" style="border-collapse:collapse; width:100%"><tr>'
    for col in df.columns:
        html += f'<th>{col}</th>'
    html += '</tr>'

    for _, row in df.iterrows():
        html += '<tr>'
        for col in df.columns:
            if col in ["DMARC", "SPF", "SPF +all", "SPF ?all"]:
                html += color_cell(row[col])
            elif col == "Security Score":
                html += color_score(row[col])
            elif col in ["MXToolbox", "Talos"]:
                html += f'<td style="text-align:center">{row[col]}</td>'
            else:
                html += f'<td>{row[col]}</td>'
        html += '</tr>'
    html += '</table>'
    return html

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

    # Sidebar filters
    st.sidebar.header("Filters")
    dmarc_filter = st.sidebar.selectbox("DMARC", ["All", "Yes", "No"])
    spf_filter = st.sidebar.selectbox("SPF", ["All", "Yes", "No"])
    plusall_filter = st.sidebar.selectbox("SPF +all", ["All", "Yes", "No"])
    qmark_filter = st.sidebar.selectbox("SPF ?all", ["All", "Yes", "No"])
    min_score = st.sidebar.slider("Minimum Security Score", 0, 100, 0)

    # Apply filters
    if dmarc_filter != "All":
        df = df[df["DMARC"] == dmarc_filter]
    if spf_filter != "All":
        df = df[df["SPF"] == spf_filter]
    if plusall_filter != "All":
        df = df[df["SPF +all"] == plusall_filter]
    if qmark_filter != "All":
        df = df[df["SPF ?all"] == qmark_filter]
    df = df[df["Security Score"] >= min_score]

    # Render table
    st.markdown(render_color_table(df), unsafe_allow_html=True)

    # Download CSV (exclude clickable columns)
    st.download_button(
        "Download results as CSV",
        df.drop(columns=["MXToolbox", "Talos"]).to_csv(index=False),
        "domain_results.csv",
        "text/csv"
    )
