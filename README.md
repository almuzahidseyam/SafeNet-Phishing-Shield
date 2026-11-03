# SafeNet · Link inspection

A local research assistant for inspecting public links: URL features, redirects,
TLS certificate evidence, page title/description and registry age. Optional Gemini
analysis explains the evidence in Bengali. It is not a phishing detector with a
validated accuracy rate, and no result certifies that a website is safe.

## Run locally

Use Python 3.12 or 3.13 in a virtual environment:

```sh
python -m venv .venv
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt -c constraints.txt
python -m streamlit run app.py --server.address=127.0.0.1
```

The basic inspection does not require an API key. For optional AI interpretation,
copy `.env.example` to `.env`, set `GEMINI_API_KEY` and an available `GEMINI_MODEL`
ID from your Google AI Studio account. Model availability changes; the application
does not silently fall back to an obsolete model. See the
[Gemini generateContent API](https://ai.google.dev/api/generate-content).

The AI checkbox is off by default. Enabling it sends extracted domain/URL features,
registry metadata and page title/description to Google, and may incur API charges.
Full URL query strings and page bodies are not included in the AI payload. The
scanner still contacts the requested public website and the RDAP registry service
when you inspect a link. Do not submit private or credential-bearing links.

## What the results mean

- **Unavailable** is a distinct state with `risk_score: null`. Missing keys,
  timeouts, provider errors and malformed model responses never become zero risk.
- A valid AI score of zero means few detected indicators, not a safe certificate.
  Scores are model-generated heuristics, not calibrated phishing probabilities.
- TLS verification means the certificate matches the connected hostname. Scam
  sites can have valid certificates too.
- Internationalized/punycode names, common words and IP-address URLs are evidence
  to review, not proof of an attack. Digits inside a domain do not make it an IP.
- A failed DNS/HTTP/registry lookup does not establish that a site is malicious.

## Network boundary

Only HTTP(S), public IP addresses and standard ports are accepted. Credentials,
control characters, local/private/reserved/multicast addresses, mixed public and
private DNS answers, and IPv6 transition addresses are rejected. Every redirect
is revalidated. The connection uses the checked numeric IP directly while TLS
checks the original hostname; DNS is not looked up again during connection.

The transport follows at most five redirects, accepts at most 256 KiB of response
body, rejects compressed bodies, and does not use ambient HTTP proxies. Optional
AI credentials are sent only to Google's fixed API host; API redirects are rejected.

All network operations run in disposable subprocesses. A page inspection gets
eight seconds, registry lookup four seconds, and optional AI analysis twenty
seconds. Timeout kills and waits for the worker, including a worker blocked in
DNS or slow response headers. Process startup has platform-dependent overhead.
There is no background WHOIS thread left running after a timeout; registry data
now uses HTTPS RDAP through the same checked transport. Unavailable registry
data remains unknown. The public suffix list is loaded from the installed package
without making a hidden download during scans.

Keep this owner-operated application on loopback. Before shared/public hosting,
add authentication, per-user quotas, outbound firewall rules and operational
monitoring. Network checks are defense in depth, not a public-service deployment
guarantee. The app's current-session result is stored in Streamlit session memory;
there is no application results database or analytics.

## Verify

```sh
python -m pip install -r requirements-dev.txt -c constraints.txt
python -m pytest -q
python -m pip_audit -r constraints.txt --no-deps --disable-pip
```

Tests exercise private destinations, redirect revalidation, DNS pinning, body
limits, API errors, response schema validation, a real timed-out subprocess, and
the rendered Streamlit unavailable states. Tests use fixtures; they do not call
Gemini or probe third-party private networks. CI repeats the suite on Windows and
Linux. Update constraints deliberately and rerun tests and the dependency audit.

Implementation: `safe_http.py` owns the network policy, `network_worker.py` owns
remote calls, `core_engine.py` owns result validation, and `app.py` renders escaped
text with native Streamlit components.

References: [Python subprocess timeout behavior](https://docs.python.org/3/library/subprocess.html#subprocess.run),
[TLS hostname verification](https://docs.python.org/3/library/http.client.html#http.client.HTTPSConnection).
