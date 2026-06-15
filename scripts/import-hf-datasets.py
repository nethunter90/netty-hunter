#!/usr/bin/env python3
"""
Import security-relevant entries from Hugging Face datasets and merge into
finetune-dataset.jsonl format (ShareGPT / Unsloth-compatible).

Sources:
  1. jondurbin/airoboros-3.1  — keyword-filtered across all categories (~570 entries)
  2. WizardLM/WizardLM_evol_instruct_V2_196k — keyword-filtered (~3k entries)

Output: scripts/hf-supplement.jsonl

Usage:
  python3 scripts/import-hf-datasets.py
"""

import json
import re
import sys
from pathlib import Path

try:
    from datasets import load_dataset
except ImportError:
    print("ERROR: Run 'pip install datasets' first")
    sys.exit(1)

ROOT     = Path(__file__).parent.parent
OUT_FILE = ROOT / "scripts" / "hf-supplement.jsonl"

SYSTEM_PROMPT = (
    "You are an expert security researcher and bug bounty hunter with deep knowledge of "
    "web application security, API security, network penetration testing, cloud infrastructure, "
    "and Kali Linux tooling. You analyze security scenarios, interpret tool output, reason about "
    "attack paths and vulnerability chains, and provide expert guidance on bug bounty tactics. "
    "Your responses are technically precise, concise, and reflect real-world bug bounty experience."
)

SECURITY_KEYWORDS = re.compile(
    r"\b(exploit|vulnerability|vuln\b|xss|sqli|sql injection|ssrf|csrf|idor|rce|lfi|rfi|"
    r"command injection|path traversal|privilege escalation|buffer overflow|"
    r"burp suite|burpsuite|nmap|ffuf|sqlmap|nuclei|metasploit|gobuster|dirb|wfuzz|"
    r"cve-\d|cwe-\d|owasp|bug bounty|penetration test|pentest|red team|"
    r"payload|bypass|authentication bypass|session hijack|"
    r"api key|secret leak|credential|hash cracking|"
    r"reverse shell|webshell|backdoor|c2 server|"
    r"recon|reconnaissance|enumeration|subdomain takeover|portscan|"
    r"waf bypass|rate limit bypass|race condition|prototype pollution|"
    r"ssti|xxe|deserialization|open redirect|cors misconfiguration|clickjacking|"
    r"insecure direct object|mass assignment|idor|broken access control)\b",
    re.IGNORECASE,
)

# Entries where the answer is defensive/corporate policy only — skip these
SKIP_PATTERNS = re.compile(
    r"\b(acceptable use policy|HR department|report to management|consult legal)\b",
    re.IGNORECASE,
)

MIN_ANSWER_LEN = 100


def is_relevant(text: str) -> bool:
    return bool(SECURITY_KEYWORDS.search(text)) and not bool(SKIP_PATTERNS.search(text))


def make_conv(human: str, gpt: str) -> dict:
    return {
        "conversations": [
            {"from": "system", "value": SYSTEM_PROMPT},
            {"from": "human",  "value": human.strip()},
            {"from": "gpt",    "value": gpt.strip()},
        ]
    }


# ─── Source 1: airoboros-3.1 (keyword-filtered, all categories) ──────────────

def pull_airoboros() -> list[dict]:
    print("\n[1/2] jondurbin/airoboros-3.1 (keyword filter across all categories) …")
    ds = load_dataset("jondurbin/airoboros-3.1", split="train")
    print(f"      Total rows: {len(ds):,}")

    results = []
    for row in ds:
        convs = row.get("conversations") or []
        human_turns = [c["value"] for c in convs if c.get("from") == "human"]
        gpt_turns   = [c["value"] for c in convs if c.get("from") == "gpt"]

        if not human_turns or not gpt_turns:
            continue

        human = human_turns[0]
        gpt   = gpt_turns[0]

        if len(gpt) < MIN_ANSWER_LEN:
            continue
        if not is_relevant(human + " " + gpt):
            continue

        results.append(make_conv(human, gpt))

    print(f"      Kept: {len(results):,}")
    return results


# ─── Source 2: WizardLM evol instruct (keyword-filtered) ─────────────────────

def pull_wizardlm() -> list[dict]:
    print("\n[2/2] WizardLM/WizardLM_evol_instruct_V2_196k (keyword filter) …")
    ds = load_dataset("WizardLM/WizardLM_evol_instruct_V2_196k", split="train")
    print(f"      Total rows: {len(ds):,}")

    results = []
    for row in ds:
        convs = row.get("conversations") or []
        human_turns = [c["value"] for c in convs if c.get("from") == "human"]
        gpt_turns   = [c["value"] for c in convs if c.get("from") == "gpt"]

        if not human_turns or not gpt_turns:
            continue

        human = human_turns[0]
        gpt   = gpt_turns[0]

        if len(gpt) < MIN_ANSWER_LEN:
            continue
        if not is_relevant(human + " " + gpt):
            continue

        results.append(make_conv(human, gpt))

    print(f"      Kept: {len(results):,}")
    return results


# ─── Deduplicate by first 120 chars of human turn ────────────────────────────

def deduplicate(convs: list[dict]) -> list[dict]:
    seen = set()
    out  = []
    for c in convs:
        key = c["conversations"][1]["value"][:120].lower().strip()
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    all_convs = []

    all_convs.extend(pull_airoboros())
    all_convs.extend(pull_wizardlm())

    before = len(all_convs)
    all_convs = deduplicate(all_convs)
    print(f"\n  Deduplication: {before:,} → {len(all_convs):,}")

    with open(OUT_FILE, "w") as f:
        for c in all_convs:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")

    size_mb = OUT_FILE.stat().st_size / 1024 / 1024
    print(f"\n{'='*60}")
    print(f"  HF supplement written : {OUT_FILE}")
    print(f"  Conversations         : {len(all_convs):,}")
    print(f"  File size             : {size_mb:.1f} MB")
    print(f"\n  Next: python3 scripts/export-finetune-jsonl.py")
    print("=" * 60)


if __name__ == "__main__":
    main()
