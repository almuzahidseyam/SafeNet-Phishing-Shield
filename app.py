import streamlit as st
from core_engine import full_scan

st.set_page_config(page_title='SafeNet · Link inspection', layout='centered')
st.title('SafeNet')
st.write('Inspect a public link before you decide to trust it.')
st.caption('A research assistant for URL, registry and page evidence. It cannot certify that a website is safe.')

with st.form('scan'):
    url = st.text_input('Website address', placeholder='https://example.com')
    use_ai = st.checkbox('Send extracted domain, registry and page-title evidence to Gemini for optional AI analysis', value=False)
    submitted = st.form_submit_button('Inspect link', type='primary')

if submitted:
    if not url.strip():
        st.warning('Enter a website address.')
    else:
        with st.spinner('Inspecting the link…'):
            st.session_state.result = full_scan(url, use_ai=use_ai)

if 'result' in st.session_state:
    result = st.session_state.result
    if result['status'] != 'ok':
        st.warning(result.get('error', 'Inspection unavailable.'))
        st.info('No safety verdict is available. A failed lookup does not mean the page is safe or malicious.')
    else:
        st.subheader('Observed evidence')
        st.text(result['final_url'])
        features, registry, tls = result['url_features'], result['whois_features'], result['ssl_details']
        age = registry.get('domain_age_days')
        left, right = st.columns(2)
        left.metric('Domain age', f'{age} days' if age is not None else 'Unavailable')
        right.metric('TLS certificate', 'Verified for hostname' if tls['verified'] else 'Not verified / HTTP')
        st.caption('A valid certificate encrypts a connection; it does not prove that a business or page is trustworthy.')
        st.write(f"Redirects followed: {result['redirects']}")
        if features['has_ip_in_domain']:
            st.write('The URL uses an IP address rather than a domain name.')
        if features['uses_punycode']:
            st.write('The domain uses internationalized characters. This alone does not prove impersonation.')
        st.write('Matched words: ' + (', '.join(features['suspicious_words']) or 'None'))
        st.caption('Common words can occur on legitimate sites; these are context, not a verdict.')
        st.text('Page title: ' + result['dom_context']['page_title'])
        if result['dom_context']['meta_description']:
            st.text(result['dom_context']['meta_description'])
        analysis = result['ai_analysis']
        st.subheader('Optional AI interpretation')
        if analysis['status'] == 'ok':
            st.metric('Heuristic indicator score', f"{analysis['risk_score']} / 100")
            st.write(analysis['verdict'])
            st.caption('This model-generated score is not a calibrated probability or a safety guarantee.')
        else:
            st.info('Analysis unavailable or not requested. No risk score has been assigned.')
        st.text(analysis['reasoning_bengali'])
