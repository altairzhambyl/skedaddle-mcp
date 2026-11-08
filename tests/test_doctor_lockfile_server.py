import json

from skedaddle_mcp import doctor
from skedaddle_mcp.lockfile import audit, read_pins


def test_doctor_reports_off_then_on(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "package.json").write_text("{}")
    rows = {r[0]: r[1] for r in doctor.report(str(tmp_path))}
    assert rows == {"npm release cooldown": False, "npm install scripts": False}
    (tmp_path / ".npmrc").write_text("min-release-age=3\nignore-scripts=true\n")
    assert all(r[1] for r in doctor.report(str(tmp_path)))


def test_doctor_pnpm_and_uv(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "pnpm-workspace.yaml").write_text("minimumReleaseAge: 0\n")
    (tmp_path / "pyproject.toml").write_text('[tool.uv]\nexclude-newer = "3 days"\n')
    rows = {r[0]: r[1] for r in doctor.report(str(tmp_path))}
    assert rows["pnpm release cooldown"] is False and rows["pnpm provenance downgrade"] is False
    assert rows["uv release cooldown"] is True


def test_lockfile_pins(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        json.dumps(
            {
                "packages": {
                    "": {"name": "app"},
                    "node_modules/axios": {"version": "1.14.1"},
                    "node_modules/a/node_modules/b": {"version": "2.0.0"},
                }
            }
        )
    )
    assert read_pins(str(lock)) == ("npm", [("axios", "1.14.1"), ("b", "2.0.0")], [])


def test_audit_flags_the_compromised_pin(registry, tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        json.dumps({"packages": {"node_modules/axios": {"version": "1.14.1"}, "node_modules/express": {"version": "5.1.0"}}})
    )
    res = audit(str(lock))
    assert res["verdict"] == "block" and res["flagged"][0]["name"] == "axios"


def test_mcp_tools_registered():
    import asyncio

    from skedaddle_mcp.server import mcp

    tools = asyncio.run(mcp.list_tools())
    assert {t.name for t in tools} == {"check_package", "audit_lockfile"}
