"""Visible value (`stats`) and a one-command, reviewed install (`install`)."""

import json


def test_stats_summarises_the_local_log(tmp_path, monkeypatch, capsys):
    from skedaddle_mcp.cli import main

    log = tmp_path / "d.jsonl"
    rows = [{"ts": "2026-11-09T10:00:00Z", "decision": "deny", "packages": ["npm:reakt-dom"], "reason": "npm package 'reakt-dom' does not exist"},
            {"ts": "2026-11-09T10:01:00Z", "decision": "deny", "packages": ["npm:next@15.0.0"], "reason": "next@15.0.0 has CRITICAL GHSA-x"},
            {"ts": "2026-11-09T10:02:00Z", "decision": "allow", "packages": ["npm:react"], "reason": ""},
            {"ts": "2026-11-09T10:03:00Z", "decision": "ask", "packages": ["-", "git source"], "reason": "a git/URL source"},
            {"ts": "2026-11-09T10:04:00Z", "decision": "warn", "packages": ["npm:x"], "reason": "mentions CVE-2024-1 only"}]
    log.write_text("".join(json.dumps(r) + "\n" for r in rows))
    monkeypatch.setenv("SKEDADDLE_LOG", str(log))
    assert main(["stats"]) == 0
    out = capsys.readouterr().out
    assert "5 installs checked" in out and "2 blocked" in out and "1 asked" in out
    assert "hallucinated names: 1" in out and "vulnerable versions: 1" in out


def test_install_prints_the_diff_and_writes_only_with_yes(tmp_path, monkeypatch, capsys):
    from skedaddle_mcp.cli import main

    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "other"}]}]}}))
    assert main(["install", "--settings", str(settings)]) == 0  # dry run: shows what would change
    assert "skedaddle-mcp hook" in capsys.readouterr().out
    assert "skedaddle" not in settings.read_text()
    assert main(["install", "--settings", str(settings), "--yes"]) == 0
    doc = json.loads(settings.read_text())
    cmds = [h["command"] for e in doc["hooks"]["PreToolUse"] for h in e["hooks"]]
    assert "other" in cmds and any(c.endswith("skedaddle-mcp hook") for c in cmds)  # existing hooks kept
    entry = next(h for e in doc["hooks"]["PreToolUse"] for h in e["hooks"] if h["command"].endswith("skedaddle-mcp hook"))
    assert entry["onFailure"] == "block" and entry["timeout"] == 60
    assert main(["install", "--settings", str(settings), "--yes"]) == 0  # idempotent
    doc2 = json.loads(settings.read_text())
    assert sum(h["command"].endswith("skedaddle-mcp hook") for e in doc2["hooks"]["PreToolUse"] for h in e["hooks"]) == 1
    assert (tmp_path / "settings.json.skedaddle-backup").exists()
