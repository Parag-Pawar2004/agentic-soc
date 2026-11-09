# Agentic SOC

A self-hosted Security Operations Center workspace. Alerts from your SIEM, IDS or
identity provider are triaged by a team of AI agents running on open-weight Llama 3
models, grounded in a Milvus RAG store of threat intelligence. The agents propose
containment (block an IP, sign a user out, suspend an account), and **nothing changes on
your firewall or identity provider until an analyst approves it** in the dashboard.

```
 SIEM / IDS / Okta ──► FastAPI ──► LangGraph agents ───────────────────────────► Next.js dashboard
   (webhook)                       supervisor → threat intel → triage → response    live reasoning trace (WebSocket)
                                        │             │                    │        approve / reject
                                   Milvus RAG     Llama 3 (OpenRouter /          ▼
                                   (your intel)   Ollama / any OpenAI-   SOAR: AWS WAF · AWS IAM · Okta · ufw/iptables
                                                  compatible server)     (runs only after approval)
```

## Quick start (no experience needed)

1. Install **Python 3.12** (https://www.python.org/downloads/ - on Windows tick *Add python.exe to PATH*)
   and **Node.js LTS** (https://nodejs.org/).
2. Open a terminal in this folder and run:

   ```bash
   python3 setup_soc.py        # Windows: py setup_soc.py
   ```

3. Answer the questions (a dashboard password, and optionally a free OpenRouter API key for hosted Llama 3).
   The script installs everything, runs the tests, and opens http://localhost:3000.
4. Press **Simulate alert** and watch the agents work.

No GPU or extra hardware is needed: Llama 3.3 70B runs on OpenRouter's free hosted tier, or
Llama 3.2 runs on your laptop's CPU through Ollama, or you can skip the LLM and use the
built-in rule-based analyst. (Groq is also supported, but Groq retired its Llama 3 models in
August 2026, so its default here is the open-weight gpt-oss-20b.)

The full illustrated walkthrough is in `docs/SETUP_GUIDE.html` and `docs/SETUP_GUIDE.ipynb`.

## Everyday commands

| Command | What it does |
|---|---|
| `python3 setup_soc.py --start` | Start the backend and dashboard |
| `python3 setup_soc.py --configure` | Change passwords, API keys or integrations |
| `python3 setup_soc.py --test` | Run the backend tests |
| `python3 setup_soc.py --doctor` | Check what's installed and running |
| `python3 setup_soc.py --github` | Publish to your GitHub and set Docker Hub secrets for CI |
| `python3 setup_soc.py --docker` | Run everything with Docker Compose instead |

## Sending real alerts

```bash
curl -X POST http://localhost:8000/api/alerts \
  -H "X-API-Key: <INGEST_API_KEY from .env>" -H "Content-Type: application/json" \
  -d '{"title":"Brute force on VPN","src_ip":"203.0.113.10","username":"alice","severity":"high",
       "category":"authentication","description":"120 failed logins in 3 minutes","raw":{"failed_attempts":120}}'
```

The interactive API explorer is at http://localhost:8000/docs.

## Threat intelligence

The RAG store starts with bundled reference notes on common attack techniques. Add your
own intel (team blocklists, past-incident notes, feeds your organisation subscribes to)
as CSV or JSON, either with **Threat intel → Add your own intel** in the dashboard or by
dropping files into `backend/data/intel_import/` (loaded on every start).

## Project layout

```
backend/            FastAPI app, LangGraph agents, RAG store, SOAR providers, tests
  app/agents/       supervisor, threat-intel, triage, response, reporter nodes + graph
  app/soar/         guardrails (policy.py) and providers (mock, AWS WAF, AWS IAM, Okta, script)
  app/intel/        CSV/JSON intel importer
frontend/           Next.js dashboard (demo mode: NEXT_PUBLIC_DEMO_MODE=1)
deploy/helm/        Helm chart for any Kubernetes cluster
deploy/terraform/   local/ = kind cluster on your laptop, aws/ = WAF IP set + IAM (+ optional EKS)
.github/workflows/  CI (tests, type-check, helm lint, terraform validate) and Docker Hub publishing
setup_soc.py        one-command setup / start / publish
tools/              make_installer.py builds the single-file installer
```

## Safety design

- Every containment action needs an analyst's approval (`AUTO_APPROVE=false` by default).
- Guardrails refuse to block private/reserved addresses or anything on `IP_ALLOWLIST`, and
  validate every target before it reaches a provider or a command line.
- Simulated alerts always go to the simulated firewall, never to a real system.
- Every decision and executed change is written to the audit trail, and blocks can be undone.

## Deploying to Kubernetes

```bash
python3 setup_soc.py --github                      # pushes code; CI builds images to Docker Hub
cd deploy/terraform/local && terraform init
terraform apply -var="dockerhub_user=YOU" -var="analyst_password=..."
```

or with Helm directly:

```bash
kubectl create secret generic agentic-soc-secrets --from-env-file=.env
helm install soc deploy/helm/agentic-soc --set image.owner=YOU --set existingSecret=agentic-soc-secrets
```
