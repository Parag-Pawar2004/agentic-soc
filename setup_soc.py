#!/usr/bin/env python3
"""Agentic SOC - one-command setup.

    python3 setup_soc.py              set everything up, then start the platform
    python3 setup_soc.py --start      just start it (after setup)
    python3 setup_soc.py --configure  change passwords / API keys / integrations
    python3 setup_soc.py --github     publish the project to your GitHub (+ Docker Hub secrets)
    python3 setup_soc.py --docker     run with Docker Compose instead of directly
    python3 setup_soc.py --test       run the backend test-suite
    python3 setup_soc.py --doctor     check what is installed and what is missing

On Windows, if "python3" opens the Microsoft Store, use:  py setup_soc.py

Only uses the Python standard library, so it works on a brand-new machine.
It only ever asks you for passwords, API keys and yes/no choices.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import platform
import re
import secrets
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"
ENV_FILE = ROOT / ".env"
IS_WIN = os.name == "nt"
VENV = BACKEND / ".venv"
VENV_PY = VENV / ("Scripts/python.exe" if IS_WIN else "bin/python")
NONINTERACTIVE = os.environ.get("SOC_SETUP_NONINTERACTIVE") == "1"

# ----------------------------------------------------------------- pretty output
if IS_WIN:
    os.system("")  # enables ANSI colours in modern Windows terminals
USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def title(text: str) -> None:
    print("\n" + _c("1;36", f"━━ {text} " + "━" * max(0, 60 - len(text))))


def ok(text: str) -> None:
    print(_c("32", "  ✔ ") + text)


def info(text: str) -> None:
    print(_c("37", "  · ") + text)


def warn(text: str) -> None:
    print(_c("33", "  ! ") + text)


def fail(text: str) -> None:
    print(_c("31", "  ✘ ") + text)


# ----------------------------------------------------------------- prompts
def ask(question: str, default: str = "", env_key: str | None = None) -> str:
    if NONINTERACTIVE:
        return os.environ.get(env_key or "", default) if env_key else default
    hint = f" [{default}]" if default else ""
    try:
        answer = input(_c("1", f"  ? {question}{hint}: ")).strip()
    except EOFError:
        answer = ""
    return answer or default


def ask_secret(question: str, current: str = "", env_key: str | None = None, optional: bool = True) -> str:
    if NONINTERACTIVE:
        return os.environ.get(env_key or "", current) if env_key else current
    hint = " [Enter = keep current]" if current else (" [Enter = skip]" if optional else "")
    while True:
        try:
            value = getpass.getpass(_c("1", f"  ? {question}{hint}: ")).strip()
        except EOFError:
            value = ""
        if value:
            return value
        if current or optional:
            return current
        warn("This one is required.")


def yes(question: str, default: bool = False, env_key: str | None = None) -> bool:
    if NONINTERACTIVE:
        val = os.environ.get(env_key or "", "")
        return val.lower() in {"1", "y", "yes", "true"} if val else default
    d = "Y/n" if default else "y/N"
    try:
        answer = input(_c("1", f"  ? {question} ({d}): ")).strip().lower()
    except EOFError:
        answer = ""
    return default if not answer else answer in {"y", "yes"}


def choose(question: str, options: list[tuple[str, str]], default: str, env_key: str | None = None) -> str:
    if NONINTERACTIVE:
        return os.environ.get(env_key or "", default) if env_key else default
    print(_c("1", f"  ? {question}"))
    for i, (key, label) in enumerate(options, 1):
        marker = _c("36", " (default)") if key == default else ""
        print(f"      {i}. {label}{marker}")
    keys = [k for k, _ in options]
    while True:
        raw = input("    Enter a number: ").strip()
        if not raw:
            return default
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return keys[int(raw) - 1]
        warn("Please type one of the numbers shown.")


# ----------------------------------------------------------------- shell helpers
def run(cmd: list[str], cwd: Path | None = None, check: bool = True, quiet: bool = False, env=None) -> int:
    info(_c("2", "$ " + " ".join(str(c) for c in cmd)))
    try:
        proc = subprocess.run(cmd, cwd=cwd, env=env,
                              stdout=subprocess.DEVNULL if quiet else None,
                              stderr=subprocess.STDOUT if quiet else None)
    except FileNotFoundError:
        fail(f"Command not found: {cmd[0]}")
        if check:
            raise SystemExit(1)
        return 127
    if check and proc.returncode != 0:
        fail(f"Command failed with exit code {proc.returncode}")
        raise SystemExit(proc.returncode)
    return proc.returncode


def capture(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception:
        return ""


def version_tuple(text: str) -> tuple[int, ...]:
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", text)
    return tuple(int(x) for x in m.groups(default="0")) if m else (0,)


# ----------------------------------------------------------------- .env handling
def read_env() -> dict[str, str]:
    env: dict[str, str] = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip('"')
    return env


ENV_LAYOUT = [
    ("Sign-in", ["ANALYST_USERNAME", "ANALYST_PASSWORD", "SECRET_KEY", "INGEST_API_KEY"]),
    ("Reasoning model (Llama 3)", ["LLM_PROVIDER", "OPENROUTER_API_KEY", "OPENROUTER_MODEL", "GROQ_API_KEY", "GROQ_MODEL", "OLLAMA_URL", "OLLAMA_MODEL",
                                   "OPENAI_COMPAT_URL", "OPENAI_COMPAT_KEY", "OPENAI_COMPAT_MODEL"]),
    ("RAG vector store", ["VECTOR_STORE", "MILVUS_URI", "EMBEDDING_BACKEND"]),
    ("Response integrations (nothing runs without your approval)",
     ["FIREWALL_PROVIDER", "IDENTITY_PROVIDER", "AWS_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
      "AWS_WAF_SCOPE", "AWS_WAF_IPSET_NAME", "AWS_WAF_IPSET_ID", "OKTA_ORG_URL", "OKTA_API_TOKEN",
      "FIREWALL_BLOCK_CMD", "FIREWALL_UNBLOCK_CMD", "IP_ALLOWLIST", "AUTO_APPROVE"]),
    ("Misc", ["DEMO_MODE", "CORS_ORIGINS"]),
]


def write_env(env: dict[str, str]) -> None:
    lines = ["# Agentic SOC settings - written by setup_soc.py. Keep this file private (it is git-ignored).", ""]
    written = set()
    for section, keys in ENV_LAYOUT:
        lines.append(f"# --- {section}")
        for k in keys:
            if k in env:
                lines.append(f"{k}={env[k]}")
                written.add(k)
        lines.append("")
    extra = [k for k in env if k not in written]
    if extra:
        lines.append("# --- Other")
        lines += [f"{k}={env[k]}" for k in extra]
    ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if not IS_WIN:
        os.chmod(ENV_FILE, 0o600)


# ----------------------------------------------------------------- steps
def check_prerequisites(need_node: bool = True) -> None:
    title("1/6  Checking your computer")
    py = sys.version_info
    if py < (3, 10):
        fail(f"Python {py.major}.{py.minor} is too old. Install Python 3.12 from https://www.python.org/downloads/")
        raise SystemExit(1)
    ok(f"Python {py.major}.{py.minor}.{py.micro} on {platform.system()} {platform.machine()}")
    if py >= (3, 14):
        warn("Python 3.14+ is very new; some packages may not have wheels yet. Python 3.12 is the safest choice.")

    if need_node:
        node = shutil.which("node")
        npm = shutil.which("npm")
        node_v = version_tuple(capture([node, "--version"])) if node else (0,)
        if not node or not npm or node_v < (18,):
            warn("Node.js 18+ is needed for the dashboard." + (f" Found {'.'.join(map(str, node_v))}." if node else ""))
            install_node()
        else:
            ok(f"Node.js {'.'.join(map(str, node_v))} with npm")

    if shutil.which("git"):
        ok("git is installed")
    else:
        warn("git is not installed (only needed to publish to GitHub): https://git-scm.com/downloads")
    if shutil.which("docker"):
        ok("Docker is installed (optional)")
    else:
        info("Docker not found - that's fine, the platform runs without it.")


def install_node() -> None:
    system = platform.system()
    if system == "Windows" and shutil.which("winget"):
        cmd = ["winget", "install", "-e", "--id", "OpenJS.NodeJS.LTS", "--accept-source-agreements",
               "--accept-package-agreements"]
    elif system == "Darwin" and shutil.which("brew"):
        cmd = ["brew", "install", "node@20"]
    elif system == "Linux" and shutil.which("apt-get"):
        cmd = ["sudo", "apt-get", "install", "-y", "nodejs", "npm"]
    else:
        cmd = []
    if cmd and yes(f"Install Node.js now with: {' '.join(cmd)}?", True):
        run(cmd, check=False)
        print()
        warn("Close this terminal, open a new one, and run the setup command again so Node.js is found.")
        raise SystemExit(0)
    fail("Install Node.js LTS from https://nodejs.org/ then run this setup again.")
    raise SystemExit(1)


def configure(reconfigure: bool = False) -> dict[str, str]:
    title("2/6  Passwords, API keys and choices")
    env = read_env()
    if env and not reconfigure:
        ok(f"Using your existing settings in {ENV_FILE.name}. (Change them with --configure.)")
        return env
    print("  Everything except the dashboard password is optional. Press Enter to skip.\n")

    env["ANALYST_USERNAME"] = ask("Dashboard username", env.get("ANALYST_USERNAME", "analyst"), "ANALYST_USERNAME")
    pw = env.get("ANALYST_PASSWORD", "")
    if not pw or reconfigure:
        if NONINTERACTIVE:
            pw = os.environ.get("ANALYST_PASSWORD") or pw or secrets.token_urlsafe(12)
        else:
            entered = ask_secret("Choose a dashboard password (Enter = generate one for me)", "" if not pw else pw)
            if not entered:
                entered = secrets.token_urlsafe(12)
                print(_c("1;33", f"    Your generated password is: {entered}   (also saved in .env)"))
            pw = entered
    env["ANALYST_PASSWORD"] = pw
    env.setdefault("SECRET_KEY", secrets.token_urlsafe(48))
    env.setdefault("INGEST_API_KEY", secrets.token_urlsafe(24))

    print()
    provider = choose(
        "Which Llama 3 model should the triage agent use?",
        [("openrouter", "OpenRouter - free hosted Llama 3.3 70B, no GPU needed (free API key) - recommended"),
         ("ollama", "Ollama on this laptop - Llama 3.2 3B, ~2 GB download, runs on CPU, slower"),
         ("groq", "Groq - very fast hosted open-weight model (gpt-oss-20b; Groq retired Llama 3)"),
         ("none", "No LLM for now (built-in rule-based analyst)")],
        env.get("LLM_PROVIDER") if env.get("LLM_PROVIDER") in {"openrouter", "groq", "ollama", "none"} else "openrouter",
        "LLM_PROVIDER",
    )
    env["LLM_PROVIDER"] = provider
    if provider == "openrouter":
        info("Get a free key at https://openrouter.ai/settings/keys (sign in, 'Create Key').")
        key = ask_secret("OpenRouter API key", env.get("OPENROUTER_API_KEY", ""), "OPENROUTER_API_KEY")
        env["OPENROUTER_API_KEY"] = key
        env.setdefault("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct")
        if not key:
            warn("No key given - agents will use the rule-based analyst until you add one.")
    elif provider == "groq":
        info("Get a free key at https://console.groq.com/keys (sign in, 'Create API Key').")
        key = ask_secret("Groq API key", env.get("GROQ_API_KEY", ""), "GROQ_API_KEY")
        env["GROQ_API_KEY"] = key
        env.setdefault("GROQ_MODEL", "openai/gpt-oss-20b")
        if not key:
            warn("No key given - agents will use the rule-based analyst until you add one.")
    elif provider == "ollama":
        env.setdefault("OLLAMA_URL", "http://localhost:11434")
        env.setdefault("OLLAMA_MODEL", "llama3.2:3b")
        setup_ollama(env["OLLAMA_MODEL"])

    print()
    better = yes("Download better AI search embeddings (~200 MB, improves threat-intel search)?",
                 env.get("EMBEDDING_BACKEND") == "fastembed", "SOC_FASTEMBED")
    env["EMBEDDING_BACKEND"] = "fastembed" if better else "hash"
    env.setdefault("VECTOR_STORE", "auto")

    print()
    env.setdefault("FIREWALL_PROVIDER", "mock")
    env.setdefault("IDENTITY_PROVIDER", "mock")
    if yes("Connect REAL response systems now (AWS WAF / Okta / AWS IAM)? Say no to use the safe simulator.",
           False, "SOC_REAL_INTEGRATIONS"):
        configure_integrations(env)
    else:
        ok("Using the simulated firewall and identity provider (safe for learning).")
    env.setdefault("AUTO_APPROVE", "false")
    env.setdefault("DEMO_MODE", "true")
    env.setdefault("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")

    write_env(env)
    ok(f"Saved settings to {ENV_FILE}")
    return env


def configure_integrations(env: dict[str, str]) -> None:
    fw = choose("Firewall to update when you approve a block:",
                [("mock", "Simulator (no real changes)"), ("aws_waf", "AWS WAF IP set"),
                 ("script", "A command on this machine (e.g. ufw / iptables)")],
                env.get("FIREWALL_PROVIDER", "mock"))
    env["FIREWALL_PROVIDER"] = fw
    if fw == "aws_waf":
        info("Tip: deploy/terraform/aws creates the IP set and a least-privilege IAM user for you.")
        env["AWS_REGION"] = ask("AWS region", env.get("AWS_REGION", "ap-south-1"))
        env["AWS_WAF_SCOPE"] = ask("WAF scope (REGIONAL or CLOUDFRONT)", env.get("AWS_WAF_SCOPE", "REGIONAL")).upper()
        env["AWS_WAF_IPSET_NAME"] = ask("WAF IP set name", env.get("AWS_WAF_IPSET_NAME", "agentic-soc-blocklist"))
        env["AWS_WAF_IPSET_ID"] = ask("WAF IP set ID", env.get("AWS_WAF_IPSET_ID", ""))
    elif fw == "script":
        env["FIREWALL_BLOCK_CMD"] = ask("Block command ({ip} is replaced)", env.get("FIREWALL_BLOCK_CMD", "sudo -n ufw insert 1 deny from {ip}"))
        env["FIREWALL_UNBLOCK_CMD"] = ask("Unblock command", env.get("FIREWALL_UNBLOCK_CMD", "sudo -n ufw delete deny from {ip}"))

    idp = choose("Identity provider for sign-out / suspend actions:",
                 [("mock", "Simulator (no real changes)"), ("okta", "Okta"), ("aws_iam", "AWS IAM (disable access keys)")],
                 env.get("IDENTITY_PROVIDER", "mock"))
    env["IDENTITY_PROVIDER"] = idp
    if idp == "okta":
        env["OKTA_ORG_URL"] = ask("Okta org URL (https://your-org.okta.com)", env.get("OKTA_ORG_URL", ""))
        env["OKTA_API_TOKEN"] = ask_secret("Okta API token", env.get("OKTA_API_TOKEN", ""))
    if fw == "aws_waf" or idp == "aws_iam":
        env["AWS_ACCESS_KEY_ID"] = ask_secret("AWS access key ID", env.get("AWS_ACCESS_KEY_ID", ""))
        env["AWS_SECRET_ACCESS_KEY"] = ask_secret("AWS secret access key", env.get("AWS_SECRET_ACCESS_KEY", ""))
    allow = ask("IPs/networks that must never be blocked (comma separated, e.g. your office IP)",
                env.get("IP_ALLOWLIST", ""))
    env["IP_ALLOWLIST"] = allow


def setup_ollama(model: str) -> None:
    if not shutil.which("ollama"):
        warn("Ollama is not installed. Get it from https://ollama.com/download, then run:")
        info(f"ollama pull {model}")
        return
    if yes(f"Download the {model} model now (~2 GB)?", True, "SOC_OLLAMA_PULL"):
        run(["ollama", "pull", model], check=False)


def install_backend(env: dict[str, str]) -> None:
    title("3/6  Installing the Python backend (FastAPI, LangGraph, Milvus)")
    if not VENV_PY.exists():
        run([sys.executable, "-m", "venv", str(VENV)])
        ok("Created a private Python environment in backend/.venv")
    run([str(VENV_PY), "-m", "pip", "install", "--upgrade", "pip"], quiet=True, check=False)
    if run([str(VENV_PY), "-m", "pip", "install", "-r", str(BACKEND / "requirements.txt")], check=False):
        fail("Installing the Python packages failed.")
        info("Check your internet connection (and any VPN/proxy), then run this setup again - it resumes.")
        info("If the error mentions building a wheel, install Python 3.12, delete backend/.venv and retry.")
        raise SystemExit(1)
    if env.get("EMBEDDING_BACKEND") == "fastembed":
        if run([str(VENV_PY), "-m", "pip", "install", "-r", str(BACKEND / "requirements-ml.txt")], check=False):
            warn("Couldn't install fastembed; falling back to built-in embeddings.")
            env["EMBEDDING_BACKEND"] = "hash"
            write_env(env)
    if env.get("FIREWALL_PROVIDER") == "aws_waf" or env.get("IDENTITY_PROVIDER") == "aws_iam":
        if env.get("AWS_ACCESS_KEY_ID"):
            ok("AWS keys stored in .env (boto3 reads them from the environment).")
    (BACKEND / "data" / "intel_import").mkdir(parents=True, exist_ok=True)
    ok("Backend installed")


def install_frontend() -> None:
    title("4/6  Installing the Next.js dashboard")
    npm = shutil.which("npm")
    if not npm:
        fail("npm not found. Install Node.js LTS from https://nodejs.org/")
        raise SystemExit(1)
    if run([npm, "install", "--no-fund", "--no-audit"], cwd=FRONTEND, check=False):
        fail("npm install failed. Check your internet connection, then run this setup again.")
        raise SystemExit(1)
    local_env = FRONTEND / ".env.local"
    if not local_env.exists():
        local_env.write_text("NEXT_PUBLIC_API_URL=http://localhost:8000\nNEXT_PUBLIC_DEMO_MODE=0\n", encoding="utf-8")
    ok("Dashboard installed")


def run_tests() -> bool:
    title("5/6  Self-test")
    if not VENV_PY.exists():
        fail("Backend isn't installed yet - run the full setup first.")
        return False
    env = {k: v for k, v in os.environ.items()}
    code = run([str(VENV_PY), "-m", "pytest", "-q", "tests"], cwd=BACKEND, check=False, env=env)
    if code == 0:
        ok("All backend tests passed")
        return True
    warn("Some tests failed - the platform may still start. Copy the output above if you need help.")
    return False


# ----------------------------------------------------------------- start / stop
def wait_for(url: str, seconds: int) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                if r.status < 500:
                    return True
        except Exception:
            time.sleep(1.5)
    return False


def _spawn(cmd: list[str], cwd: Path, log: Path) -> subprocess.Popen:
    log.parent.mkdir(parents=True, exist_ok=True)
    handle = open(log, "w", encoding="utf-8")
    kwargs: dict = {"cwd": cwd, "stdout": handle, "stderr": subprocess.STDOUT}
    if IS_WIN:
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(cmd, **kwargs)


def _stop(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        if IS_WIN:
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
        else:
            os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=10)
    except Exception:
        proc.kill()


def start(open_browser: bool = True) -> None:
    title("6/6  Starting Agentic SOC")
    if not VENV_PY.exists() or not (FRONTEND / "node_modules").exists():
        fail("Not installed yet. Run:  python3 setup_soc.py")
        raise SystemExit(1)
    env = read_env()
    logs = ROOT / "logs"
    backend = _spawn([str(VENV_PY), "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"],
                     BACKEND, logs / "backend.log")
    frontend = _spawn([shutil.which("npm") or "npm", "run", "dev"], FRONTEND, logs / "frontend.log")
    procs = [backend, frontend]
    try:
        info("Waiting for the backend (first start loads the intel store)…")
        if not wait_for("http://127.0.0.1:8000/api/health", 120):
            fail("Backend didn't start. Last lines of logs/backend.log:")
            print(_tail(logs / "backend.log"))
            raise SystemExit(1)
        ok("Backend running   →  http://localhost:8000/docs  (API explorer)")
        info("Waiting for the dashboard (first start compiles it, ~30 s)…")
        if not wait_for("http://127.0.0.1:3000", 180):
            fail("Dashboard didn't start. Last lines of logs/frontend.log:")
            print(_tail(logs / "frontend.log"))
            raise SystemExit(1)
        ok("Dashboard running →  http://localhost:3000")
        print()
        print(_c("1", f"  Sign in as  {env.get('ANALYST_USERNAME', 'analyst')}  with the password in .env (ANALYST_PASSWORD)."))
        print("  Press “Simulate alert” in the dashboard to watch the agents work.")
        print(_c("2", "  Logs are in the logs/ folder. Press Ctrl+C here to stop everything."))
        if open_browser:
            webbrowser.open("http://localhost:3000")
        while all(p.poll() is None for p in procs):
            time.sleep(1)
        warn("A process stopped unexpectedly. See the logs/ folder.")
    except KeyboardInterrupt:
        print()
        info("Stopping…")
    finally:
        for p in procs:
            _stop(p)
        ok("Stopped. Start again any time with:  python3 setup_soc.py --start")


def _tail(path: Path, n: int = 25) -> str:
    try:
        return "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[-n:])
    except OSError:
        return "(no log)"


def docker_up() -> None:
    title("Starting with Docker Compose")
    if not shutil.which("docker"):
        fail("Docker isn't installed. Get Docker Desktop: https://www.docker.com/products/docker-desktop/")
        raise SystemExit(1)
    if not ENV_FILE.exists():
        configure()
    run(["docker", "compose", "up", "--build", "-d"], cwd=ROOT)
    if wait_for("http://127.0.0.1:3000", 300):
        ok("Running → http://localhost:3000   (stop with: docker compose down)")
        webbrowser.open("http://localhost:3000")
    else:
        warn("Still starting. Check: docker compose logs -f")


# ----------------------------------------------------------------- GitHub publishing
def github_api(method: str, path: str, token: str, body: dict | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(
        f"https://api.github.com{path}", method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "agentic-soc-setup"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}


def publish_github() -> None:
    title("Publish to GitHub")
    if not shutil.which("git"):
        fail("git is required: https://git-scm.com/downloads")
        raise SystemExit(1)
    print("  You need a GitHub personal access token (classic) with the 'repo' and 'workflow' scopes:")
    print("  https://github.com/settings/tokens/new?scopes=repo,workflow&description=agentic-soc-setup\n")
    token = ask_secret("GitHub token", "", "GITHUB_TOKEN", optional=False)
    status, me = github_api("GET", "/user", token)
    if status != 200:
        fail(f"GitHub rejected the token ({status}): {me.get('message', '')}")
        raise SystemExit(1)
    user = me["login"]
    ok(f"Signed in to GitHub as {user}")
    repo = ask("Repository name", "agentic-soc", "SOC_REPO_NAME")
    private = yes("Make the repository private?", True, "SOC_REPO_PRIVATE")

    status, data = github_api("POST", "/user/repos", token, {
        "name": repo, "private": private, "description": "Self-hosted agentic SOC: AI triage agents + human-approved response",
    })
    if status == 201:
        ok(f"Created https://github.com/{user}/{repo}")
    elif status == 422:
        info(f"Repository {user}/{repo} already exists - pushing to it.")
    else:
        fail(f"Couldn't create the repository ({status}): {data.get('message', '')}")
        raise SystemExit(1)

    if not (ROOT / ".git").exists():
        run(["git", "init", "-b", "main"], cwd=ROOT)
    name = capture(["git", "-C", str(ROOT), "config", "user.name"]) or me.get("name") or user
    email = capture(["git", "-C", str(ROOT), "config", "user.email"]) or f"{me['id']}+{user}@users.noreply.github.com"
    run(["git", "-c", f"user.name={name}", "-c", f"user.email={email}", "add", "-A"], cwd=ROOT)
    run(["git", "-c", f"user.name={name}", "-c", f"user.email={email}", "commit", "-m",
         "Agentic SOC platform", "--allow-empty"], cwd=ROOT, check=False)
    remote = f"https://github.com/{user}/{repo}.git"
    if capture(["git", "-C", str(ROOT), "remote", "get-url", "origin"]):
        run(["git", "remote", "set-url", "origin", remote], cwd=ROOT)
    else:
        run(["git", "remote", "add", "origin", remote], cwd=ROOT)
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    # The token is passed for this one command only; it is never written to git config.
    run(["git", "-c", f"http.https://github.com/.extraheader=AUTHORIZATION: basic {basic}",
         "push", "-u", "origin", "main"], cwd=ROOT)
    ok(f"Pushed. Your code: https://github.com/{user}/{repo}")

    print()
    if yes("Set up Docker Hub so GitHub Actions builds and pushes your images?", True, "SOC_SETUP_DOCKERHUB"):
        print("  Create a Docker Hub access token: https://app.docker.com/settings/personal-access-tokens")
        hub_user = ask("Docker Hub username", "", "DOCKERHUB_USERNAME")
        hub_token = ask_secret("Docker Hub access token", "", "DOCKERHUB_TOKEN", optional=False)
        if hub_user and hub_token:
            set_actions_secret(token, user, repo, "DOCKERHUB_USERNAME", hub_user)
            set_actions_secret(token, user, repo, "DOCKERHUB_TOKEN", hub_token)
            ok("Saved as GitHub Actions secrets. Images build on every push to main:")
            info(f"https://github.com/{user}/{repo}/actions")
            values = ROOT / "deploy" / "helm" / "agentic-soc" / "values.yaml"
            text = values.read_text(encoding="utf-8")
            if "owner: yourdockerhubuser" in text:
                values.write_text(text.replace("owner: yourdockerhubuser", f"owner: {hub_user}"), encoding="utf-8")
                info("Updated the Helm chart to pull your images. Run --github again to push that change.")


def set_actions_secret(token: str, owner: str, repo: str, name: str, value: str) -> None:
    """GitHub requires secrets to be encrypted with the repo's public key (libsodium sealed box)."""
    status, key = github_api("GET", f"/repos/{owner}/{repo}/actions/secrets/public-key", token)
    if status != 200:
        fail(f"Couldn't read the repo's secret key ({status}).")
        return
    python = str(VENV_PY) if VENV_PY.exists() else sys.executable
    if subprocess.run([python, "-c", "import nacl"], capture_output=True).returncode != 0:
        run([python, "-m", "pip", "install", "-q", "pynacl"], check=False)
    script = (
        "import base64,sys;from nacl import encoding,public;"
        "pk=public.PublicKey(sys.argv[1].encode(),encoding.Base64Encoder());"
        "print(base64.b64encode(public.SealedBox(pk).encrypt(sys.stdin.read().encode())).decode())"
    )
    enc = subprocess.run([python, "-c", script, key["key"]], input=value, capture_output=True, text=True)
    if enc.returncode != 0:
        fail(f"Couldn't encrypt {name}: {enc.stderr.strip()[:200]}")
        return
    status, _ = github_api("PUT", f"/repos/{owner}/{repo}/actions/secrets/{name}", token,
                           {"encrypted_value": enc.stdout.strip(), "key_id": key["key_id"]})
    (ok if status in (201, 204) else fail)(f"GitHub secret {name}: {'saved' if status in (201, 204) else status}")


# ----------------------------------------------------------------- doctor
def doctor() -> None:
    title("Doctor")
    check_prerequisites(need_node=False)
    for label, path in [("Settings (.env)", ENV_FILE), ("Backend environment", VENV_PY),
                        ("Dashboard packages", FRONTEND / "node_modules")]:
        (ok if path.exists() else warn)(f"{label}: {'present' if path.exists() else 'missing - run the full setup'}")
    env = read_env()
    if env:
        info(f"LLM provider: {env.get('LLM_PROVIDER', 'auto')}, firewall: {env.get('FIREWALL_PROVIDER', 'mock')}, "
             f"identity: {env.get('IDENTITY_PROVIDER', 'mock')}")
    for name, url in [("Backend", "http://127.0.0.1:8000/api/health"), ("Dashboard", "http://127.0.0.1:3000")]:
        up = wait_for(url, 2)
        (ok if up else info)(f"{name} {'is running' if up else 'is not running'}")


# ----------------------------------------------------------------- main
def main() -> None:
    parser = argparse.ArgumentParser(description="Set up and run Agentic SOC")
    parser.add_argument("--start", action="store_true", help="start the platform (after setup)")
    parser.add_argument("--configure", action="store_true", help="change passwords, keys and integrations")
    parser.add_argument("--github", action="store_true", help="publish to your GitHub and set Docker Hub secrets")
    parser.add_argument("--docker", action="store_true", help="run with Docker Compose")
    parser.add_argument("--test", action="store_true", help="run the backend tests")
    parser.add_argument("--doctor", action="store_true", help="check the installation")
    parser.add_argument("--no-start", action="store_true", help="set up but don't start")
    parser.add_argument("--no-browser", action="store_true", help="don't open the browser")
    args = parser.parse_args()

    print(_c("1;36", "\n  Agentic SOC  ·  setup\n") + _c("2", f"  Project folder: {ROOT}"))
    os.chdir(ROOT)
    if args.doctor:
        return doctor()
    if args.test:
        raise SystemExit(0 if run_tests() else 1)
    if args.start:
        return start(not args.no_browser)
    if args.docker:
        return docker_up()
    if args.github:
        return publish_github()
    if args.configure:
        configure(reconfigure=True)
        ok("Done. Restart with:  python3 setup_soc.py --start")
        return

    check_prerequisites()
    env = configure()
    install_backend(env)
    install_frontend()
    run_tests()
    if yes("Publish this project to your GitHub now? (you can do it later with --github)", False, "SOC_PUBLISH"):
        publish_github()
    if args.no_start:
        ok("Setup finished. Start any time with:  python3 setup_soc.py --start")
        return
    start(not args.no_browser)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n  Cancelled.")
