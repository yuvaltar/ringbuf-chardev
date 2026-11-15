#!/usr/bin/env python3
"""Triage a failed test/fuzz log: extract and deduplicate the failure
reports, map them to the security requirements in SECURITY.md, and, when
ANTHROPIC_API_KEY is set, ask an LLM for a root-cause hypothesis and a
suggested fix. Prints Markdown (CI appends it to the job summary).

usage: triage.py LOG [--offline]

The deterministic part (extraction, deduplication, reproducer command)
always runs; the LLM part is advisory and never changes the CI verdict.
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Report headers, most specific first. Each report runs until the next
# header, a test-section marker, or 60 lines.
HEADERS = [
    ("KASAN", re.compile(r"BUG: KASAN: [\w-]+ in (\S+)")),
    ("hardened usercopy", re.compile(r"usercopy: Kernel memory (?:exposure|overwrite) attempt detected (?:from|to) (.*?) \(offset")),
    ("UBSAN", re.compile(r"UBSAN: ([\w-]+ in \S+)")),
    ("lockdep", re.compile(r"WARNING: (possible (?:circular|recursive) locking.*|"
                           r"suspicious RCU usage)")),
    ("hung task", re.compile(r"INFO: task (\S+) blocked for more than")),
    ("kmemleak", re.compile(r"unreferenced object (0x[0-9a-f]+)")),
    ("sleep in atomic", re.compile(r"BUG: sleeping function called from invalid context at (\S+)")),
    ("WARN", re.compile(r"WARNING: CPU: \d+ PID: \d+ at (\S+)")),
    ("oops", re.compile(r"(BUG: unable to handle .*|general protection fault.*|Oops: .*|"
                        r"invalid opcode: .*|Kernel panic - .*)")),
    ("model divergence", re.compile(r"FUZZ FAILURE \(seed (\d+), op (\d+)\): (.*)")),
    ("stress failure", re.compile(r"STRESS FAILURE \(seed (\d+)\): (.*)")),
    ("test failure", re.compile(r"\[ FAIL \] (\S+)")),
]
END = re.compile(r"^(=== |RESULT: |\[ +OK +\]|\[ FAIL \]|FUZZ FAILURE|STRESS FAILURE)")
TS = re.compile(r"^\[\s*\d+\.\d+\]\s?")


def extract(lines):
    """Return [(kind, title, body)] in order of first appearance, deduplicated."""
    reports, seen, i = [], set(), 0
    while i < len(lines):
        line = TS.sub("", lines[i])
        for kind, rx in HEADERS:
            m = rx.search(line)
            if not m:
                continue
            title = line.strip()
            body = [line]
            j = i + 1
            while j < len(lines) and j - i < 60 and not END.match(TS.sub("", lines[j])):
                if any(r.search(TS.sub("", lines[j])) for _, r in HEADERS):
                    break
                body.append(TS.sub("", lines[j]))
                j += 1
            # Deduplicate on kind + location, ignoring addresses and seeds.
            key = (kind, re.sub(r"0x[0-9a-f]+|\d+", "N", m.group(1)))
            if key not in seen:
                seen.add(key)
                reports.append((kind, title, "\n".join(body).rstrip()))
            i = j - 1
            break
        i += 1
    return reports


def reproducer(reports, log):
    """Command line that replays the failing fuzz run, if the log has one."""
    for kind, title, _ in reports:
        m = re.search(r"seed (\d+)", title)
        if m:
            seed = int(m.group(1))
            if kind == "stress failure":
                return f"FUZZ_SEED={seed} make qemu-fuzz   # stress phase"
            return f"FUZZ_SEED={seed} make qemu-fuzz"
    m = re.search(r"seed (\d+)", log)
    return f"FUZZ_SEED={m.group(1)} make fuzz-debug" if m else None


def ask_llm(reports, api_key):
    driver = open(os.path.join(ROOT, "driver/ringbuf.c")).read()
    security = open(os.path.join(ROOT, "SECURITY.md")).read()
    failures = "\n\n".join(f"[{k}] {body}" for k, _, body in reports)[:20000]
    prompt = (
        "You are triaging a failure in a Linux character device driver.\n"
        "For each distinct failure below, answer in Markdown with: the security "
        "requirement from SECURITY.md it violates (if any), the most likely root "
        "cause with function and line in driver/ringbuf.c, severity "
        "(critical/high/medium/low) with a one-line justification, and a minimal "
        "fix as a unified diff. Say plainly when the evidence is insufficient. "
        "Be concise.\n\n"
        f"<failures>\n{failures}\n</failures>\n\n"
        f"<security_md>\n{security}\n</security_md>\n\n"
        f"<driver>\n{driver}\n</driver>\n"
    )
    req = urllib.request.Request(
        os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com") + "/v1/messages",
        data=json.dumps({
            "model": os.environ.get("TRIAGE_MODEL", "claude-sonnet-5-5"),
            "max_tokens": 2000,
            "messages": [{"role": "user", "content": prompt}],
        }).encode(),
        headers={
            "content-type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.load(resp)
    return "".join(b.get("text", "") for b in data.get("content", []))


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    log = open(sys.argv[1], errors="replace").read().replace("\r", "")
    reports = extract(log.splitlines())

    print("### Failure triage\n")
    if not reports:
        print("No failure reports found in the log.")
        return 0
    print(f"{len(reports)} distinct failure(s):\n")
    for kind, title, body in reports:
        print(f"<details><summary><b>{kind}</b>: {title[:150]}</summary>\n")
        print("```\n" + body + "\n```\n</details>\n")
    rep = reproducer(reports, log)
    if rep:
        print(f"Reproduce locally: `{rep}`\n")

    key = os.environ.get("ANTHROPIC_API_KEY")
    if "--offline" in sys.argv or not key:
        print("_LLM analysis skipped (no ANTHROPIC_API_KEY)._")
        return 0
    try:
        print("#### LLM analysis (advisory)\n")
        print(ask_llm(reports, key))
    except (urllib.error.URLError, OSError, ValueError) as e:
        print(f"_LLM analysis failed: {e}_")
    return 0


if __name__ == "__main__":
    sys.exit(main())
