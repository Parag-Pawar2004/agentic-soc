Put CSV or JSON threat-intel files you are allowed to use here (your team's blocklist,
notes from past incidents...). They are loaded into the RAG store every time the backend starts.

CSV columns understood: value, kind, title, description, tags, source, url

Example (example_blocklist.csv):
value,title,description,tags
203.0.113.66,Old incident attacker,Brute-forced VPN in March,vpn;brute-force
