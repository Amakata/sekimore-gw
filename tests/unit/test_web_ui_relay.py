"""Web UI の Relay タブ API（/api/relay/*）のテスト — /data/relay を読むだけで変更系は無い."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from src.web_ui import relay_view

CONFIG_WITH_RELAY = """
allow_domains: [github.com]
domain_handlers:
  github.com: {handler: git-relay}
relay:
  https: passthrough
  bootstrap: auto
  token_ttl: 12h
  state_dir: "{state_dir}"
  project:
    name: case-a
    repos:
      - {name: Org/App, mode: read-write, bases: [main]}
      - {name: Org/Lib, mode: read-only}
    permissions: [pr:create, issue:comment]
"""

AUDIT_LINES = [
    '{"actor":"system","domain":"github.com","event":"serve_started","project":"case-a","ts":"2026-09-14T14:27:05Z","via":"sekimore-gateway"}',
    '{"actor":"agent-via-gateway","event":"ssh_auth_ok","fingerprint":"SHA256:abc","peer":"192.168.0.3:55766","ts":"2026-09-14T14:22:42Z","via":"sekimore-gateway"}',
    '{"actor":"agent-via-gateway","bytes_in":"4","bytes_out":"481","event":"relay_ok","ms":"1994","peer":"192.168.0.3:55766","repo":"Org/App","status":"0","ts":"2026-09-14T14:22:44Z","verb":"git-upload-pack","via":"sekimore-gateway"}',
    '{"actor":"agent-via-gateway","event":"repo_denied","kind":"repo_not_in_project","peer":"192.168.0.3:55770","reason":"repository \\"x/y\\" is not in project \\"case-a\\"","repo":"x/y.git","ts":"2026-09-14T14:22:45Z","verb":"git-upload-pack","via":"sekimore-gateway"}',
    '{"actor":"agent-via-gateway","event":"api_error","label":"skm_b99fc15a","path":"/pr/close","reason":"pr:close is not allowed by policy","repo":"Org/App","status":"403","ts":"2026-09-14T18:01:21Z","via":"sekimore-gateway"}',
    '{"actor":"agent-via-gateway","event":"token_denied","path":"/whoami","peer":"192.168.0.3","reason":"unknown token","ts":"2026-09-14T18:00:30Z","via":"sekimore-gateway"}',
    "this line is not json",
    '{"actor":"agent-via-gateway","bytes_in":"756","bytes_out":"587215","event":"https_passthrough","peer":"192.168.0.3:49946","ts":"2026-09-14T18:00:30.123456789Z","upstream":"github.com","via":"sekimore-gateway"}',
]

TOKENS_JSON = {
    "records": {
        "a" * 64: {
            "label": "skm_aaaaaaaa",
            "project": "case-a",
            "issued_at": "2026-09-14T12:00:00Z",
            "expires_at": "2099-01-01T00:00:00Z",
            "last_used": "2026-09-14T13:00:00.5Z",
            "use_count": 7,
            "revoked": False,
        },
        "b" * 64: {
            "label": "skm_bbbbbbbb",
            "project": "case-a",
            "issued_at": "2026-09-14T11:00:00Z",
            "expires_at": "2099-01-01T00:00:00Z",
            "revoked": True,
        },
        "c" * 64: {
            "label": "skm_cccccccc",
            "project": "case-a",
            "issued_at": "2026-09-13T11:00:00Z",
            "expires_at": "2026-09-13T23:00:00Z",
        },
    }
}


def _write_state(tmp_path: Path) -> tuple[Path, Path]:
    state = tmp_path / "relay"
    state.mkdir()
    (state / "tokens.json").write_text(json.dumps(TOKENS_JSON))
    (state / "audit.jsonl").write_text("\n".join(AUDIT_LINES) + "\n")
    (state / "authorized_keys").write_text(
        "ssh-ed25519 AAAA one\n# comment\nssh-ed25519 BBBB two\n"
    )
    (state / "known_hosts").write_text("github.com ssh-ed25519 AAAA\n")
    (state / "upstream_token").write_text("gho_secret")
    cfg = tmp_path / "config.yml"
    cfg.write_text(CONFIG_WITH_RELAY.replace("{state_dir}", str(state)))
    return cfg, state


def describe_parse_ts():
    def it_parses_rfc3339_with_and_without_fraction():
        assert relay_view.parse_ts("2026-09-14T14:27:05Z") == pytest.approx(1789396025.0)
        assert relay_view.parse_ts("2026-09-14T14:27:05.5Z") == pytest.approx(1789396025.5)
        assert relay_view.parse_ts("2026-09-14T14:27:05.123456789Z") == pytest.approx(
            1789396025.123456789
        )

    def it_rejects_garbage():
        assert relay_view.parse_ts(None) is None
        assert relay_view.parse_ts("yesterday") is None
        assert relay_view.parse_ts(12345) is None


def describe_relay_api():
    def it_reports_disabled_when_no_git_relay_handler(tmp_path):
        cfg = tmp_path / "config.yml"
        cfg.write_text("allow_domains: [example.com]\n")
        with patch("src.web_ui.app.CONFIG_PATH", str(cfg)):
            from src.web_ui.app import app

            client = TestClient(app)
            data = client.get("/api/relay/config").json()
            assert data["enabled"] is False and data["domain"] is None and data["state_files"] == []
            stats = client.get("/api/relay/stats").json()
            assert stats == {
                "enabled": False,
                "allowed": 0,
                "blocked": 0,
                "tokens_active": 0,
                "tokens_total": 0,
                "keys": 0,
            }
            assert client.get("/api/relay/tokens").json() == []
            assert client.get("/api/relay/audit").json() == []

    def it_returns_config_permissions_repos_and_state_files(tmp_path):
        cfg, state = _write_state(tmp_path)
        with patch("src.web_ui.app.CONFIG_PATH", str(cfg)):
            from src.web_ui.app import app

            data = TestClient(app).get("/api/relay/config").json()
        assert data["enabled"] is True
        assert data["domain"] == "github.com" and data["upstream"] == "github.com"
        assert data["project"] == "case-a"
        assert data["permissions"] == ["issue:comment", "pr:create"]
        assert data["repos"] == [
            {"name": "Org/App", "mode": "read-write", "bases": ["main"], "push": ["sekimore/*"]},
            {"name": "Org/Lib", "mode": "read-only", "bases": [], "push": ["sekimore/*"]},
        ]
        assert data["state_dir"] == str(state)
        files = {f["name"]: f for f in data["state_files"]}
        assert files["authorized_keys"] == {"name": "authorized_keys", "present": True, "count": 2}
        assert files["known_hosts"]["count"] == 1
        assert files["upstream_token"]["present"] is True and "count" in files["upstream_token"]
        assert files["host_key"]["present"] is False
        assert data["bootstrap_disabled"] is False
        # 秘密はレスポンスに含まれない
        assert "gho_secret" not in json.dumps(data)

    def it_lists_tokens_without_hashes_newest_first(tmp_path):
        cfg, _state = _write_state(tmp_path)
        with patch("src.web_ui.app.CONFIG_PATH", str(cfg)):
            from src.web_ui.app import app

            resp = TestClient(app).get("/api/relay/tokens")
        tokens = resp.json()
        assert [t["label"] for t in tokens] == ["skm_aaaaaaaa", "skm_bbbbbbbb", "skm_cccccccc"]
        assert [t["state"] for t in tokens] == ["active", "revoked", "expired"]
        assert tokens[0]["use_count"] == 7 and tokens[0]["last_used"] == pytest.approx(1789390800.5)
        assert "a" * 64 not in resp.text  # ハッシュ（キー）は出さない

    def it_splits_audit_into_access_and_block_history(tmp_path):
        cfg, _state = _write_state(tmp_path)
        with patch("src.web_ui.app.CONFIG_PATH", str(cfg)):
            from src.web_ui.app import app

            client = TestClient(app)
            allowed = client.get("/api/relay/audit?kind=allowed").json()
            blocked = client.get("/api/relay/audit?kind=blocked").json()
            everything = client.get("/api/relay/audit?kind=all&limit=3").json()
        # 新しい順（ファイル末尾が先頭）。壊れた行は無視
        assert [e["event"] for e in allowed] == ["https_passthrough", "relay_ok", "ssh_auth_ok"]
        assert all(e["action"] == "ALLOWED" for e in allowed)
        assert (
            allowed[0]["component"] == "HTTPS"
            and allowed[0]["detail"] == "bytes_in=756 bytes_out=587215"
        )
        assert allowed[0]["timestamp"] == pytest.approx(1789408830.123456789)
        assert allowed[1]["repo"] == "Org/App" and allowed[1]["verb"] == "git-upload-pack"
        assert [e["event"] for e in blocked] == ["token_denied", "api_error", "repo_denied"]
        assert all(e["action"] == "BLOCKED" for e in blocked)
        assert blocked[1]["component"] == "API" and blocked[1]["label"] == "skm_b99fc15a"
        assert blocked[1]["reason"] == "pr:close is not allowed by policy"
        assert blocked[2]["detail"] == "kind=repo_not_in_project"
        assert len(everything) == 3
        assert everything[-1]["event"] == "api_error"  # limit は新しい順に効く

    def it_counts_stats_over_last_24h_only(tmp_path):
        cfg, _state = _write_state(tmp_path)
        with (
            patch("src.web_ui.app.CONFIG_PATH", str(cfg)),
            patch("src.web_ui.relay_view.datetime") as dt,
        ):
            from datetime import UTC, datetime

            dt.now.return_value = datetime(2026, 9, 14, 20, 0, tzinfo=UTC)
            dt.strptime = datetime.strptime
            from src.web_ui.app import app

            stats = TestClient(app).get("/api/relay/stats").json()
        assert stats == {
            "enabled": True,
            "allowed": 3,
            "blocked": 3,
            "tokens_active": 1,
            "tokens_total": 3,
            "keys": 2,
        }

    def it_handles_missing_state_files(tmp_path):
        cfg = tmp_path / "config.yml"
        cfg.write_text(CONFIG_WITH_RELAY.replace("{state_dir}", str(tmp_path / "nope")))
        with patch("src.web_ui.app.CONFIG_PATH", str(cfg)):
            from src.web_ui.app import app

            client = TestClient(app)
            assert client.get("/api/relay/tokens").json() == []
            assert client.get("/api/relay/audit").json() == []
            data = client.get("/api/relay/config").json()
            assert data["enabled"] is True and all(not f["present"] for f in data["state_files"])

    def it_has_no_write_endpoints():
        from src.web_ui.app import app

        methods = {
            m
            for r in app.routes
            if getattr(r, "path", "").startswith("/api/relay")
            for m in r.methods
        }
        assert methods == {"GET"}

    def it_serves_the_relay_tab_in_the_dashboard():
        from src.web_ui.app import app

        html = TestClient(app).get("/").text
        assert (
            'id="tab-relay"' in html and "switchTab('relay')" in html and "/api/relay/audit" in html
        )


def describe_relay_route_registration_order():
    """/api/relay/* が __main__ ブロック (uvicorn.run) より前で登録されること.

    バグ: relay エンドポイントを app.py 末尾 (if __name__ == '__main__': uvicorn.run(app) の後) に
    追記していたため、`python -m src.web_ui.app` で起動すると uvicorn.run の時点で app に relay ルートが
    まだ無く、実プロセスが 404 を返していた (import 経由のテストでは登録済みに見えて検出できなかった)。
    """

    def it_defines_relay_routes_before_the_main_block():
        src = (Path(__file__).parents[2] / "src" / "web_ui" / "app.py").read_text()
        main_pos = src.index('if __name__ == "__main__":')
        for route in (
            "/api/relay/config",
            "/api/relay/stats",
            "/api/relay/tokens",
            "/api/relay/audit",
        ):
            pos = src.index(f'"{route}"')
            assert pos < main_pos, (
                f"{route} は __main__ ブロックより前で定義すること (実プロセスで 404 になる)"
            )

    def it_registers_relay_routes_on_the_app():
        from src.web_ui.app import app

        paths = {r.path for r in app.routes}
        assert {
            "/api/relay/config",
            "/api/relay/stats",
            "/api/relay/tokens",
            "/api/relay/audit",
        } <= paths
