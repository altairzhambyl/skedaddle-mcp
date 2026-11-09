"""Parsing regressions found while researching agent threats (the self-modification guard itself is a separate tool)."""

from skedaddle_mcp.hook import plan


def test_heredoc_prose_is_not_an_install(tmp_path):
    """Text written to a file is not executed (a research note mentioning 'npm install evil-pkg' was blocked)."""
    cmd = "cat > notes.md <<'EOF'\nShai-Hulud: npm install hook worm\nthen run npm install evil-pkg\nEOF"
    assert plan(cmd, str(tmp_path), {}) == ([], [])
    # a heredoc is data ONLY when it is the whole command; anything after it means the body is checked too
    # (fails closed, review of 2bc5857: every narrower rule had a bypass)
    cmd2 = 'cat <<EOF > n.md\nnpm i zzq-x\nEOF\nnpm i left-pad'
    assert plan(cmd2, str(tmp_path), {})[0] == [("npm", "zzq-x"), ("npm", "left-pad")]


def test_heredoc_fed_to_an_interpreter_is_still_checked(tmp_path):
    """review of 4f4d939: `bash <<EOF` EXECUTES its body; only data sinks (cat, tee) make it data."""
    for cmd in ("bash <<'EOF'\nnpm i zzq-evil\nEOF", "sh -s <<EOF\nnpm i zzq-evil\nEOF", "ssh host <<EOF\nnpm i zzq-evil\nEOF",
                "cat > x <<EOF\nunterminated\nnpm i zzq-evil"):  # no closing delimiter: fail closed, keep the lines
        assert ("npm", "zzq-evil") in plan(cmd, str(tmp_path), {})[0], cmd


def test_heredoc_sink_that_is_piped_or_run_later_is_checked(tmp_path):
    """review of 8d18fb6: `cat <<EOF | bash` and `cat > x.sh <<EOF ... ; bash x.sh` execute the body."""
    for cmd in ("cat <<'EOF' | bash\nnpm i zzq-evil\nEOF", "cat <<EOF | sh -s\nnpm i zzq-evil\nEOF",
                "cat > x.sh <<'EOF'\nnpm i zzq-evil\nEOF\nbash x.sh", "tee run.sh <<EOF >/dev/null\nnpm i zzq-evil\nEOF\nsource run.sh"):
        assert ("npm", "zzq-evil") in plan(cmd, str(tmp_path), {})[0], cmd


def test_heredoc_data_only_when_it_is_the_whole_command(tmp_path):
    """review of 2bc5857: line continuations, quoted targets, references before the heredoc, sensitive targets."""
    for cmd in ("cat > 'x.sh' \\\n <<EOF\nnpm i zzq-evil\nEOF", "bash x.sh; cat > x.sh <<EOF\nnpm i zzq-evil\nEOF",
                "cat > ~/.bashrc <<EOF\nnpm i zzq-evil\nEOF", "cat > .git/hooks/pre-commit <<EOF\nnpm i zzq-evil\nEOF",
                "cat > Makefile <<EOF\nnpm i zzq-evil\nEOF", "cat > \"$F\" <<EOF\nnpm i zzq-evil\nEOF"):
        assert ("npm", "zzq-evil") in plan(cmd, str(tmp_path), {})[0], cmd
