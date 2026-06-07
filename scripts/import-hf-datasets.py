#!/usr/bin/env python3
"""
Import security-relevant entries from Hugging Face datasets and merge into
finetune-dataset.jsonl format (ShareGPT / Unsloth-compatible).

Sources:
  1. jondurbin/airoboros-3.1  — hacking category, already ShareGPT format
  2. CyberNative-AI/Cybersecurity_training_dataset_v1 — security Q&A

Output: scripts/hf-supplement.jsonl  (merged alongside finetune-dataset.jsonl)

Usage:
  python3 scripts/import-hf-datasets.py
  # Then re-run export-finetune-jsonl.py which will pick up hf-supplement.jsonl
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

# Keywords that indicate a security-relevant entry worth keeping
SECURITY_KEYWORDS = re.compile(
    r"\b(exploit|vulnerability|vuln|xss|sqli|sql injection|ssrf|csrf|idor|rce|lfi|rfi|"
    r"command injection|path traversal|privilege escalation|buffer overflow|"
    r"burp suite|nmap|ffuf|sqlmap|nuclei|metasploit|gobuster|dirb|"
    r"cve-\d|cwe-\d|owasp|bug bounty|penetration test|pentest|"
    r"payload|bypass|authentication|authorization|session|token|"
    r"api key|secret|credential|password|hash|encryption|tls|ssl|"
    r"reverse shell|webshell|backdoor|c2|command.and.control|"
    r"recon|reconnaissance|enumeration|subdomain|portscan|"
    r"waf bypass|rate limit|race condition|prototype pollution|"
    r"ssti|xxe|deserialization|open redirect|cors|clickjacking)\b",
    re.IGNORECASE,
)

# Minimum answer length to keep (filter out one-liners)
MIN_ANSWER_LEN = 80


def is_relevant(text: str) -> bool:
    return bool(SECURITY_KEYWORDS.search(text))


def make_conv(human: str, gpt: str, system: str = SYSTEM_PROMPT) -> dict:
    return {
        "conversations": [
            {"from": "system", "value": system},
            {"from": "human",  "value": human.strip()},
            {"from": "gpt",    "value": gpt.strip()},
        ]
    }


# ─── Source 1: airoboros-3.1 (hacking category) ───────────────────────────────

def pull_airoboros() -> list[dict]:
    print("\n[1/2] Downloading jondurbin/airoboros-3.1 …")
    ds = load_dataset("jondurbin/airoboros-3.1", split="train")
    print(f"      Total rows: {len(ds):,}")

    results = []
    skipped_category = 0
    skipped_length   = 0
    skipped_relevance = 0

    for row in ds:
        category = (row.get("category") or "").lower()
        # Keep hacking, security, and orca entries that are security-flavored
        if category not in ("hacking", "security"):
            skipped_category += 1
            continue

        convs = row.get("conversations") or []
        if len(convs) < 2:
            continue

        # Already in ShareGPT format — extract human/gpt turns
        human_turns = [c["value"] for c in convs if c.get("from") == "human"]
        gpt_turns   = [c["value"] for c in convs if c.get("from") == "gpt"]

        if not human_turns or not gpt_turns:
            continue

        human = human_turns[0]
        gpt   = gpt_turns[0]

        if len(gpt) < MIN_ANSWER_LEN:
            skipped_length += 1
            continue

        if not is_relevant(human + " " + gpt):
            skipped_relevance += 1
            continue

        results.append(make_conv(human, gpt))

    print(f"      Kept: {len(results):,}  "
          f"(skipped category={skipped_category:,}, "
          f"short={skipped_length:,}, off-topic={skipped_relevance:,})")
    return results


# ─── Source 2: CyberNative cybersecurity dataset ──────────────────────────────

def pull_cybernative() -> list[dict]:
    print("\n[2/2] Downloading CyberNative-AI/Cybersecurity_training_dataset_v1 …")
    try:
        ds = load_dataset(
            "CyberNative-AI/Cybersecurity_training_dataset_v1",
            split="train",
            trust_remote_code=True,
        )
    except Exception as e:
        print(f"      WARNING: Could not load dataset — {e}")
        return []

    print(f"      Total rows: {len(ds):,}")

    results = []
    skipped = 0

    for row in ds:
        # Dataset has 'instruction', 'input', 'output' fields (Alpaca format)
        instruction = (row.get("instruction") or "").strip()
        inp         = (row.get("input") or "").strip()
        output      = (row.get("output") or "").strip()

        if not instruction or not output:
            skipped += 1
            continue

        if len(output) < MIN_ANSWER_LEN:
            skipped += 1
            continue

        human = f"{instruction}\n{inp}".strip() if inp else instruction

        if not is_relevant(human + " " + output):
            skipped += 1
            continue

        results.append(make_conv(human, output))

    print(f"      Kept: {len(results):,}  (skipped/filtered: {skipped:,})")
    return results


# ─── Deduplicate by first 120 chars of human turn ─────────────────────────────

def deduplicate(convs: list[dict]) -> list[dict]:
    seen = set()
    out  = []
    for c in convs:
        key = c["conversations"][1]["value"][:120].lower().strip()
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    all_convs = []

    all_convs.extend(pull_airoboros())
    all_convs.extend(pull_cybernative())

    before = len(all_convs)
    all_convs = deduplicate(all_convs)
    print(f"\n  Deduplication: {before:,} → {len(all_convs):,}")

    with open(OUT_FILE, "w") as f:
        for c in all_convs:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")

    size_mb = OUT_FILE.stat().st_size / 1024 / 1024
    print(f"\n{'='*60}")
    print(f"  HF supplement written: {OUT_FILE}")
    print(f"  Conversations : {len(all_convs):,}")
    print(f"  File size     : {size_mb:.1f} MB")
    print(f"\n  Next step: re-run export-finetune-jsonl.py")
    print(f"  It will automatically include hf-supplement.jsonl")
    print("=" * 60)


if __name__ == "__main__":
    main()
