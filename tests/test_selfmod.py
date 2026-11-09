"""Parsing regressions found while researching agent threats (the self-modification guard itself is a separate tool)."""

from skedaddle_mcp.hook import plan


def test_heredoc_prose_is_not_an_install(tmp_path):
    """Text written to a file is not executed (a research note mentioning 'npm install evil-pkg' was blocked)."""
    cmd = "cat > notes.md <<'EOF'\nShai-Hulud: npm install hook worm\nthen run npm install evil-pkg\nEOF"
    assert plan(cmd, str(tmp_path), {}) == ([], [])
    cmd2 = 'cat <<EOF > n.md\nnpm i zzq-x\nEOF\nnpm i left-pad'
    assert plan(cmd2, str(tmp_path), {})[0] == [("npm", "left-pad")]  # the real command after the heredoc still counts


def test_heredoc_fed_to_an_interpreter_is_still_checked(tmp_path):
    """review of 4f4d939: `bash <<EOF` EXECUTES its body; only data sinks (cat, tee) make it data."""
    for cmd in ("bash <<'EOF'\nnpm i zzq-evil\nEOF", "sh -s <<EOF\nnpm i zzq-evil\nEOF", "ssh host <<EOF\nnpm i zzq-evil\nEOF",
                "cat > x <<EOF\nunterminated\nnpm i zzq-evil"):  # no closing delimiter: fail closed, keep the lines
        assert ("npm", "zzq-evil") in plan(cmd, str(tmp_path), {})[0], cmd
