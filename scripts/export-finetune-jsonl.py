#!/usr/bin/env python3
"""
Export the expanded prompt dataset to Unsloth-compatible ShareGPT JSONL.
Output: scripts/finetune-dataset.jsonl   (~ready to upload to Colab)

Run standalone:  python3 scripts/export-finetune-jsonl.py
Or auto-chained by expand-dataset.py when generation completes.

Unsloth Colab notebook (free T4 GPU):
  https://colab.research.google.com/github/unslothai/unsloth/blob/main/notebooks/Unsloth_Qwen2.5_(7B)_Alpaca.ipynb
  Switch base model to: unsloth/Qwen2.5-3B-Instruct
  Upload finetune-dataset.jsonl when prompted for training data.
"""

import json
from pathlib import Path

ROOT        = Path(__file__).parent.parent
PROMPTS_DIR = ROOT / "server" / "data" / "prompts"
OUT_FILE    = ROOT / "scripts" / "finetune-dataset.jsonl"

SYSTEM_PROMPT = (
    "You are an expert security researcher and bug bounty hunter with deep knowledge of "
    "web application security, API security, network penetration testing, cloud infrastructure, "
    "and Kali Linux tooling. You analyze security scenarios, interpret tool output, reason about "
    "attack paths and vulnerability chains, and provide expert guidance on bug bounty tactics. "
    "Your responses are technically precise, concise, and reflect real-world bug bounty experience."
)


def make_human_turn(entry: dict) -> str:
    """Build the human prompt from the entry's context fields + prompt."""
    parts = []

    # Context labels — include any that are present and non-empty
    CONTEXT_FIELDS = [
        ("access_level",       "Access Level"),
        ("auth_domain",        "Auth Domain"),
        ("cloud_domain",       "Cloud Domain"),
        ("domain",             "Domain"),
        ("signal_type",        "Signal Type"),
        ("engagement_context", "Engagement Context"),
        ("vulnerability_type", "Vulnerability Type"),
        ("tool",               "Tool"),
        ("tools_involved",     "Tools Involved"),
        ("complexity",         "Complexity"),
        ("objective",          "Objective"),
        ("chain_steps",        "Chain Steps"),
        ("signal_observed",    "Signal Observed"),
        ("impact_level",       "Impact Level"),
    ]

    for field, label in CONTEXT_FIELDS:
        val = entry.get(field)
        if not val:
            continue
        if isinstance(val, list):
            val = ", ".join(str(v) for v in val)
        parts.append(f"{label}: {val}")

    if entry.get("scenario"):
        parts.append(f"\nScenario:\n{entry['scenario']}")

    parts.append(f"\n{entry['prompt']}")

    return "\n".join(parts)


def make_gpt_turn(entry: dict) -> str:
    return entry["expected_answer"].strip()


def export():
    conversations = []
    file_stats = []

    for json_file in sorted(PROMPTS_DIR.glob("*.json")):
        data = json.loads(json_file.read_text())
        count_before = len(conversations)

        for entry in data:
            if not entry.get("prompt") or not entry.get("expected_answer"):
                continue
            # Skip if expected_answer is suspiciously short (< 30 chars)
            if len(entry["expected_answer"].strip()) < 30:
                continue

            conversations.append({
                "conversations": [
                    {"from": "system", "value": SYSTEM_PROMPT},
                    {"from": "human",  "value": make_human_turn(entry)},
                    {"from": "gpt",    "value": make_gpt_turn(entry)},
                ]
            })

        added = len(conversations) - count_before
        file_stats.append((json_file.name, added))

    # Write JSONL
    with open(OUT_FILE, "w") as f:
        for conv in conversations:
            f.write(json.dumps(conv, ensure_ascii=False) + "\n")

    size_mb = OUT_FILE.stat().st_size / 1024 / 1024

    print("\n" + "=" * 60)
    print("Fine-tune dataset export complete")
    print("=" * 60)
    for fname, count in file_stats:
        print(f"  {fname:48s}  {count:>5} entries")
    print(f"\n  Total conversations : {len(conversations):,}")
    print(f"  Output file         : {OUT_FILE}")
    print(f"  File size           : {size_mb:.1f} MB")
    print("""
─── How to fine-tune with this file ──────────────────────────

1. Open the Unsloth Colab notebook (free T4 GPU):
   https://colab.research.google.com/github/unslothai/unsloth/blob/main/notebooks/Unsloth_Qwen2.5_(7B)_Alpaca.ipynb

2. Change the base model to:
   model_name = "unsloth/Qwen2.5-3B-Instruct"

3. Upload finetune-dataset.jsonl when prompted for training data.
   Set dataset_type = "sharegpt"

4. Run all cells.  Colab T4 (free tier):
   - 3B model, ~10k examples, 3 epochs ≈ 2–4 hours

5. Download the exported .gguf file from the output cell.

6. Import into Ollama on your local machine:
   Create a file called 'Modelfile' with:
     FROM /path/to/your-model-Q4_K_M.gguf
   Then run:
     ollama create sentinel-security -f Modelfile

7. Update server/.env:
   OLLAMA_DEFAULT_MODEL=sentinel-security

Your purpose-built bug bounty model is live.
""")


if __name__ == "__main__":
    export()
