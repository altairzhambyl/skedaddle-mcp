"""`stats` (what skedaddle did for you, from the local log) and `install` (the Claude Code hook, reviewed and reversible)."""

from __future__ import annotations

import collections
import json
import os
import shutil
import sys

from .hook import log_path

HOOK_ENTRY = {"type": "command", "command": "skedaddle-mcp hook", "timeout": 60, "onFailure": "block"}


def stats(_args: list[str]) -> int:
    path = log_path()
    rows = []
    try:
        with open(path or "", encoding="utf-8") as fh:
            rows = [json.loads(x) for x in fh if x.strip()]
    except (OSError, ValueError):
        pass
    if not rows:
        print(f"no decisions logged yet ({path or 'logging is off: SKEDADDLE_LOG=0'})")
        return 0
    by = collections.Counter(r.get("decision") for r in rows)
    reasons = " ".join(str(r.get("reason") or "") for r in rows if r.get("decision") == "deny")
    kinds = {
        "hallucinated names": reasons.count("does not exist"),
        "vulnerable versions": sum(
            1 for r in rows if r.get("decision") == "deny" and ("GHSA-" in str(r.get("reason")) or "CVE-" in str(r.get("reason")))
        ),
        "malware / takedowns": reasons.count("malicious") + reasons.count("taken down"),
        "compromised-release signals": sum(
            reasons.count(k) for k in ("provenance", "removed from the registry", "install-time code")
        ),
        "dependency confusion": reasons.count("dependency confusion"),
    }
    first, last = rows[0].get("ts", "?"), rows[-1].get("ts", "?")
    print(
        f"skedaddle, {first[:10]} .. {last[:10]}: {len(rows)} installs checked, {by.get('deny', 0)} blocked, "
        f"{by.get('ask', 0)} asked, {by.get('warn', 0)} warned"
    )
    for k, v in kinds.items():
        if v:
            print(f"  {k}: {v}")
    print(f"log: {path} (local only)")
    return 0


def install(args: list[str]) -> int:
    """Add the PreToolUse hook to Claude Code settings. Dry run by default: prints the change; --yes writes it, keeping
    a backup and every existing hook. Idempotent."""
    target = (
        args[args.index("--settings") + 1]
        if "--settings" in args
        else os.path.join(os.path.expanduser("~"), ".claude", "settings.json")
    )
    try:
        with open(target, encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        doc = {}
    except ValueError as e:
        print(f"{target} is not valid JSON ({e}); not touching it", file=sys.stderr)
        return 3
    pre = doc.setdefault("hooks", {}).setdefault("PreToolUse", [])
    if any(h.get("command", "").endswith("skedaddle-mcp hook") for e in pre for h in e.get("hooks") or []):
        print(f"already installed in {target}")
        return 0
    entry = {"matcher": "Bash", "hooks": [dict(HOOK_ENTRY)]}
    print(f"would add to {target} -> hooks.PreToolUse:\n{json.dumps(entry, indent=2)}")
    if "--yes" not in args:
        print("dry run: re-run with --yes to write it (a backup is kept next to the file)")
        return 0
    if os.path.exists(target):
        shutil.copy2(target, target + ".skedaddle-backup")
    pre.append(entry)
    os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
    tmp = target + ".skedaddle-tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, target)
    print(f"installed; backup: {target}.skedaddle-backup. Undo: restore the backup or delete the entry.")
    return 0
