# DSPM Shadow-AI Egress Guard

A three-part, fully local Data Security Posture Management (DSPM) proof of
concept that detects and blocks employees/devices pasting sensitive or
proprietary data into external LLM tools ("shadow AI"):

1. **`classifier/`** — FastAPI service that classifies text as `Safe` or
   `Sensitive/Proprietary` using a local spaCy NLP model (via Presidio) plus
   custom pattern recognizers for API keys/secrets and financial markers.
   No external API calls.
2. **`proxy/`** — a `mitmproxy` addon that intercepts outbound POST traffic,
   sends the extracted text to the classifier, and blocks (403s) anything
   flagged as sensitive. All events are logged to SQLite.
3. **`dashboard/`** — a live Streamlit dashboard over that SQLite log.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

## Run

Open three terminals, from the project root in each:

```bash
# 1. Classification backend
uvicorn classifier.main:app --host 0.0.0.0 --port 8000
```

```bash
# 2. Egress proxy (explicit HTTP(S) proxy on port 8080)
mitmdump -s proxy/addon.py --listen-port 8080
```

```bash
# 3. Dashboard
streamlit run dashboard/app.py
```

### Quick test of the classifier alone

```bash
curl -X POST http://localhost:8000/classify \
  -H "Content-Type: application/json" \
  -d '{"source_ip": "192.168.1.50", "text_content": "Here is our AWS key: AKIAABCDEFGHIJKLMNOP"}'

curl -X POST http://localhost:8000/classify \
  -H "Content-Type: application/json" \
  -d '{"source_ip": "192.168.1.50", "text_content": "What is a good recipe for banana bread?"}'
```

### Pointing a device at the proxy

Point the device's HTTP(S) proxy settings at `<this-machine-ip>:8080`, then
install mitmproxy's CA certificate on the device (it's generated on first
run at `~/.mitmproxy/mitmproxy-ca-cert.pem`) so it can inspect HTTPS. On the
device, visit `http://mitm.it` while proxied through this machine for
platform-specific install instructions.

`proxy/devices.json` maps source IPs to friendly labels and a type
(`workstation` / `ot_sensor` / `other`) shown on the dashboard — edit it to
match your lab's IPs.

## Known limitations (be aware of these before treating this as production DLP)

- **Certificate pinning**: apps/devices that pin TLS certificates (many
  mobile apps, some IoT firmware) will refuse to connect through a MITM
  proxy at all, pinned or not — this approach can't see their traffic.
- **Embedded/OT devices**: many microcontrollers (e.g. ESP32-class modules)
  have limited or no support for configuring an upstream HTTP(S) proxy or
  trusting a custom CA. For those, egress inspection normally has to happen
  at the network layer (a transparent proxy on the gateway using
  `mitmproxy`'s transparent mode + `iptables`/`nftables` redirection on the
  Ubuntu host acting as router) rather than per-device proxy configuration.
  That setup is Linux-only and out of scope for this proof of concept.
- **Fail-open by default**: if the classifier is unreachable, `proxy/addon.py`
  allows traffic through rather than blocking the network (`FAIL_OPEN=true`
  env var). Set `FAIL_OPEN=false` for a stricter default-deny posture.
- **This intercepts and can decrypt TLS traffic on your network.** Only run
  it against devices you own/administer and have consent to inspect, and
  disclose it to anyone whose traffic passes through it, per your
  organization's policy and applicable law.

## Tuning false positives

`classifier/engine.py` implements a two-tier scoring policy: high-precision
entities (validated formats like credit-card/SSN, or literal secret
patterns like AWS/GitHub/Stripe keys) flag on a single hit; low-precision
signals (generic NER, loose keyword context) only flag when at least two
corroborate each other. Thresholds live at the top of that file
(`HIGH_PRECISION_THRESHOLD`, `SUPPORTING_THRESHOLD`,
`MIN_SUPPORTING_CORROBORATION`) — raise them if you're seeing too many false
positives, lower them if leaks are slipping through.
