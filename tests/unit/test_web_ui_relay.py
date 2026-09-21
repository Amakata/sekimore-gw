"""Tests for the Web UI Relay tab API (/api/relay/*) — read-only over /data/relay, no mutations."""

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
                "large_uploads": 0,
                "upload_capped": 0,
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
            {
                "name": "Org/App",
                "host": "github.com",
                "mode": "read-write",
                "bases": ["main"],
                "push": ["sekimore/*"],
                "tags": [],
                "delete": False,
                "permissions": ["issue:comment", "pr:create"],
            },
            {
                "name": "Org/Lib",
                "host": "github.com",
                "mode": "read-only",
                "bases": [],
                "push": ["sekimore/*"],
                "tags": [],
                "delete": False,
                "permissions": ["issue:comment", "pr:create"],
            },
        ]
        assert data["tags"] == [] and data["allow_tags"] is False and data["permissions_deny"] == []
        assert data["state_dir"] == str(state)
        files = {f["name"]: f for f in data["state_files"]}
        assert files["authorized_keys"] == {"name": "authorized_keys", "present": True, "count": 2}
        assert files["known_hosts"]["count"] == 1
        assert files["upstream_token"]["present"] is True and "count" in files["upstream_token"]
        assert files["host_key"]["present"] is False
        assert data["bootstrap_disabled"] is False
        # Secrets never make it into the response
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
        assert "a" * 64 not in resp.text  # The hash (the key) is not exposed

    def it_splits_audit_into_access_and_block_history(tmp_path):
        cfg, _state = _write_state(tmp_path)
        with patch("src.web_ui.app.CONFIG_PATH", str(cfg)):
            from src.web_ui.app import app

            client = TestClient(app)
            allowed = client.get("/api/relay/audit?kind=allowed").json()
            blocked = client.get("/api/relay/audit?kind=blocked").json()
            everything = client.get("/api/relay/audit?kind=all&limit=3").json()
        # Newest first (end of file comes first). Malformed lines are skipped
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
        assert everything[-1]["event"] == "api_error"  # limit applies to the newest-first ordering

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
            "large_uploads": 0,
            "upload_capped": 0,
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
    """/api/relay/* must be registered before the __main__ block (uvicorn.run).

    Bug: the relay endpoints were appended to the end of app.py (after
    `if __name__ == '__main__': uvicorn.run(app)`), so starting with `python -m src.web_ui.app`
    reached uvicorn.run before the relay routes existed and the real process returned 404
    (tests that import the app saw them registered, so they missed it).
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
                f"{route} must be defined before the __main__ block, or it 404s in the real process"
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


def describe_per_repo_policy():
    """0.1.9: project defaults + per-repo diffs (deny wins), tags globs, delete, and folding in legacy relay.allow_*."""

    config_text = """
domain_handlers:
  github.com: {handler: git-relay}
relay:
  allow_tags: true
  state_dir: "{state_dir}"
  project:
    name: case-a
    permissions: {allow: [pr:create, pr:read, ci:read], deny: [issue:label]}
    tags: []
    repos:
      - {name: Org/App, mode: read-write, bases: [main], tags: ["v*"], permissions: {add_is_not_a_key: 1}}
      - {name: Org/Lib, mode: read-only, permissions: {allow: [pr:merge, issue:label], deny: [ci:read]}}
      - {name: Org/Old, mode: read-only, permissions: [pr:read], delete: true}
"""

    def it_computes_effective_permissions_tags_and_delete(tmp_path):
        cfg = tmp_path / "config.yml"
        cfg.write_text(config_text.replace("{state_dir}", str(tmp_path / "relay")))
        with patch("src.web_ui.app.CONFIG_PATH", str(cfg)):
            from src.web_ui.app import app

            data = TestClient(app).get("/api/relay/config").json()
        # Project defaults: allow − deny. Legacy relay.allow_tags: true folds into ["*"] when project.tags is empty
        assert data["permissions"] == ["ci:read", "pr:create", "pr:read"]
        assert data["permissions_deny"] == ["issue:label"]
        assert (
            data["tags"] == ["*"] and data["allow_tags"] is True and data["allow_delete"] is False
        )
        repos = {r["name"]: r for r in data["repos"]}
        # App: malformed repo permissions (a dict with no allow/deny) → no diff; tags come from the repo as ["v*"]
        assert repos["Org/App"]["permissions"] == ["ci:read", "pr:create", "pr:read"]
        assert repos["Org/App"]["tags"] == ["v*"] and repos["Org/App"]["delete"] is False
        # Lib: allow adds pr:merge and issue:label, but the project deny on issue:label and the repo deny on ci:read strip them out
        assert repos["Org/Lib"]["permissions"] == ["pr:create", "pr:merge", "pr:read"]
        assert repos["Org/Lib"]["tags"] == ["*"]  # Unspecified → project default
        # Old: a bare list adds to allow (it does not replace), and delete is set to true on the repo
        assert repos["Org/Old"]["permissions"] == ["ci:read", "pr:create", "pr:read"]
        assert repos["Org/Old"]["delete"] is True


def describe_multi_upstream():
    """0.2.0: several git-relay domains split across ports — default upstream, per-upstream state, per-repo host."""

    config_text = """
domain_handlers:
  github.com: {handler: git-relay}
  ghe.example.com: {handler: git-relay, ssh_port: 2222}
relay:
  state_dir: "{state_dir}"
  project:
    name: case-m
    permissions: [pr:create]
    repos:
      - {name: Org/App, mode: read-write, bases: [main]}
      - {name: ghe.example.com/Corp/Internal, mode: read-write, bases: [main]}
"""

    def it_lists_upstreams_default_first_with_per_upstream_state(tmp_path):
        state = tmp_path / "relay"
        (state / "upstreams" / "ghe.example.com").mkdir(parents=True)
        (state / "upstream_token").write_text("gho_x")
        (state / "upstreams" / "ghe.example.com" / "known_hosts").write_text(
            "[ghe.example.com]:22 ssh-ed25519 AAAA\n"
        )
        cfg = tmp_path / "config.yml"
        cfg.write_text(config_text.replace("{state_dir}", str(state)))
        with patch("src.web_ui.app.CONFIG_PATH", str(cfg)):
            from src.web_ui.app import app

            data = TestClient(app).get("/api/relay/config").json()
        assert data["enabled"] is True
        # The 0.1.x fields point at the default upstream (github.com, the one without an ssh_port)
        assert data["domain"] == "github.com" and data["upstream"] == "github.com"
        ups = data["upstreams"]
        assert [u["domain"] for u in ups] == ["github.com", "ghe.example.com"]
        assert ups[0]["default"] is True and ups[0]["ssh_port"] == 22
        assert ups[0]["token_present"] is True and ups[0]["api_base"] == "https://api.github.com"
        assert ups[1]["default"] is False and ups[1]["ssh_port"] == 2222
        assert ups[1]["token_present"] is False and ups[1]["known_hosts_count"] == 1
        assert ups[1]["api_base"] == "https://ghe.example.com/api/v3"
        repos = {r["name"]: r for r in data["repos"]}
        assert repos["Org/App"]["host"] == "github.com"
        assert repos["Corp/Internal"]["host"] == "ghe.example.com"
        files = {f["name"]: f for f in data["state_files"]}
        assert files["upstreams/ghe.example.com/upstream_token"]["present"] is False
        assert files["upstreams/ghe.example.com/known_hosts"]["count"] == 1
        # Secrets (the upstream token itself) never appear in the response
        assert "gho_x" not in json.dumps(data)

    def it_picks_default_true_when_every_entry_has_an_ssh_port(tmp_path):
        text = config_text.replace(
            "github.com: {handler: git-relay}", "github.com: {handler: git-relay, ssh_port: 2201}"
        ).replace(
            "ghe.example.com: {handler: git-relay, ssh_port: 2222}",
            "ghe.example.com: {handler: git-relay, ssh_port: 2222, default: true}",
        )
        cfg = tmp_path / "config.yml"
        cfg.write_text(text.replace("{state_dir}", str(tmp_path / "relay")))
        with patch("src.web_ui.app.CONFIG_PATH", str(cfg)):
            from src.web_ui.app import app

            data = TestClient(app).get("/api/relay/config").json()
        assert data["domain"] == "ghe.example.com"
        assert [u["domain"] for u in data["upstreams"]] == ["ghe.example.com", "github.com"]
        assert data["upstreams"][0]["ssh_port"] == 2222
        # A repo with no host belongs to the default upstream (ghe.example.com)
        assert {r["name"]: r["host"] for r in data["repos"]}["Org/App"] == "ghe.example.com"


def describe_upstream_policy_layer():
    """0.2.1: the project.upstreams.<domain> layer — permission diffs, push / tags / delete defaults, repos."""

    config_text = """
domain_handlers:
  github.com: {handler: git-relay}
  ghe.example.com: {handler: git-relay, ssh_port: 2222}
relay:
  state_dir: "{state_dir}"
  project:
    name: case-m
    permissions: [pr:read, ci:read]
    upstreams:
      github.com:
        permissions: {allow: [pr:create, pr:merge]}
        tags: ["v*"]
        repos:
          - {name: Org/App, mode: read-write, bases: [main]}
          - {name: Org/Tool, mode: read-write, tags: [], permissions: {deny: [pr:merge]}}
      ghe.example.com:
        permissions: {allow: [pr:create], deny: [pr:merge]}
        delete: true
        repos:
          - {name: Corp/Internal, mode: read-write, bases: [main]}
    repos:
      - {name: ghe.example.com/Corp/Legacy, mode: read-only}
"""

    def it_applies_upstream_defaults_and_permission_diffs(tmp_path):
        cfg = tmp_path / "config.yml"
        cfg.write_text(config_text.replace("{state_dir}", str(tmp_path / "relay")))
        with patch("src.web_ui.app.CONFIG_PATH", str(cfg)):
            from src.web_ui.app import app

            data = TestClient(app).get("/api/relay/config").json()
        assert data["permissions"] == ["ci:read", "pr:read"]
        repos = {(r["host"], r["name"]): r for r in data["repos"]}
        app_ = repos[("github.com", "Org/App")]
        assert app_["permissions"] == ["ci:read", "pr:create", "pr:merge", "pr:read"]
        assert app_["tags"] == ["v*"] and app_["delete"] is False
        tool = repos[("github.com", "Org/Tool")]
        assert tool["permissions"] == ["ci:read", "pr:create", "pr:read"]  # The repo deny wins
        assert tool["tags"] == []  # Overridden by the repo
        internal = repos[("ghe.example.com", "Corp/Internal")]
        assert internal["permissions"] == ["ci:read", "pr:create", "pr:read"]
        assert internal["delete"] is True and internal["tags"] == []
        legacy = repos[
            ("ghe.example.com", "Corp/Legacy")
        ]  # A host prefix in project.repos also picks up the upstream layer
        assert legacy["delete"] is True
        assert legacy["permissions"] == ["ci:read", "pr:create", "pr:read"]
        assert len(data["repos"]) == 4

    def it_prefers_the_handler_api_base_and_lists_ssh_options(tmp_path):
        # 0.2.1: even when upstream is a bastion/forward target, api_base comes from the handler, and ssh_options are ordered relay first, then handler
        text = config_text.replace(
            "ghe.example.com: {handler: git-relay, ssh_port: 2222}",
            "ghe.example.com: {handler: git-relay, ssh_port: 2222, upstream: host.docker.internal, "
            "api_base: 'https://ghe.example.com/api/v3', ssh_options: [ProxyJump=bastion.example.com]}",
        ).replace(
            '  state_dir: "{state_dir}"',
            '  state_dir: "{state_dir}"\n  ssh_options: [ConnectionAttempts=2]',
        )
        cfg = tmp_path / "config.yml"
        cfg.write_text(text.replace("{state_dir}", str(tmp_path / "relay")))
        with patch("src.web_ui.app.CONFIG_PATH", str(cfg)):
            from src.web_ui.app import app

            data = TestClient(app).get("/api/relay/config").json()
        ups = {u["domain"]: u for u in data["upstreams"]}
        assert ups["ghe.example.com"]["upstream"] == "host.docker.internal"
        assert ups["ghe.example.com"]["api_base"] == "https://ghe.example.com/api/v3"
        assert ups["ghe.example.com"]["ssh_options"] == [
            "ConnectionAttempts=2",
            "ProxyJump=bastion.example.com",
        ]
        assert ups["github.com"]["ssh_options"] == ["ConnectionAttempts=2"]
        assert ups["github.com"]["api_base"] == "https://api.github.com"


def describe_upload_caps_and_https_relay():
    """0.2.2: upload caps (default / per-upstream / https-relay) and detection of large or over-cap uploads."""

    config_text = """
domain_handlers:
  github.com: {handler: git-relay, max_upload_bytes: 262144}
  ghcr.io: {handler: https-relay, max_upload_bytes: -1}
  registry-1.docker.io: {handler: https-relay}
relay:
  https_max_upload_bytes: 4194304
  state_dir: "{state_dir}"
  project:
    name: case-c
    permissions: [pr:create]
    repos:
      - {name: Org/App, mode: read-write, bases: [main]}
"""
    audit_lines = [
        '{"actor":"agent-via-gateway","bytes_in":"512","bytes_out":"9000","event":"https_passthrough","peer":"192.168.0.3:1","sni":"github.com","ts":"2099-01-01T00:00:01Z","upstream":"github.com","via":"sekimore-gateway"}',
        '{"actor":"agent-via-gateway","bytes_in":"5242880","bytes_out":"100","event":"https_passthrough","peer":"192.168.0.3:2","sni":"ghcr.io","ts":"2099-01-01T00:00:02Z","upstream":"ghcr.io","via":"sekimore-gateway"}',
        '{"actor":"agent-via-gateway","bytes_in":"262145","cap":"262144","event":"https_upload_capped","peer":"192.168.0.3:3","reason":"upload exceeded max_upload_bytes; connection closed","sni":"github.com","ts":"2099-01-01T00:00:03Z","upstream":"github.com","via":"sekimore-gateway"}',
    ]

    def it_reports_caps_per_target_and_flags_large_or_capped_uploads(tmp_path):
        state = tmp_path / "relay"
        state.mkdir()
        (state / "audit.jsonl").write_text("\n".join(audit_lines) + "\n")
        cfg = tmp_path / "config.yml"
        cfg.write_text(config_text.replace("{state_dir}", str(state)))
        with patch("src.web_ui.app.CONFIG_PATH", str(cfg)):
            from src.web_ui.app import app

            client = TestClient(app)
            conf = client.get("/api/relay/config").json()
            stats = client.get("/api/relay/stats").json()
            allowed = client.get("/api/relay/audit?kind=allowed").json()
            blocked = client.get("/api/relay/audit?kind=blocked").json()
        assert conf["https_max_upload_bytes"] == 4194304
        assert conf["upstreams"][0]["max_upload_bytes"] == 262144  # handler beats the default
        assert [(t["domain"], t["max_upload_bytes"]) for t in conf["https_relays"]] == [
            ("ghcr.io", -1),
            ("registry-1.docker.io", 4194304),
        ]
        big = [
            e for e in allowed if e["event"] == "https_passthrough" and e["flag"] == "large_upload"
        ]
        assert len(big) == 1 and "bytes_in=5242880" in big[0]["detail"]
        small = [e for e in allowed if e["event"] == "https_passthrough" and e["flag"] is None]
        assert len(small) == 1
        capped = [e for e in blocked if e["event"] == "https_upload_capped"]
        assert len(capped) == 1 and capped[0]["component"] == "HTTPS"
        assert stats["large_uploads"] == 1 and stats["upload_capped"] == 1


def describe_dashboard_permission_list():
    """The Relay tab offers a fixed list of permission keys; it must match the relay's own set."""

    def it_lists_every_key_the_relay_defines():
        import re
        from pathlib import Path

        root = Path(__file__).resolve().parents[2]
        html = (root / "src" / "web_ui" / "templates" / "dashboard.html").read_text()
        policy = (root / "relay" / "src" / "policy.rs").read_text()

        m = re.search(r"const allPerms = \[(.*?)\];", html, re.S)
        assert m, "the dashboard should declare allPerms"
        shown = set(re.findall(r"'([a-z_]+:[a-z_]+)'", m.group(1)))

        # Rebuild the relay's set from valid_actions(): `Resource::X => &[A, B],`
        actions = {
            "Create": "create",
            "Comment": "comment",
            "Review": "review",
            "RequestReview": "request_review",
            "Merge": "merge",
            "Close": "close",
            "Label": "label",
            "Assign": "assign",
            "Read": "read",
            "AddItem": "add_item",
            "UpdateItem": "update_item",
            "Publish": "publish",
            "Rerun": "rerun",
            "Update": "update",
        }
        defined = set()
        for res, body in re.findall(r"Resource::(\w+) => &\[([^\]]*)\]", policy):
            for a in (x.strip() for x in body.split(",") if x.strip()):
                assert a in actions, f"unknown action {a}; add it to this test"
                defined.add(f"{res.lower()}:{actions[a]}")

        assert defined, "should have parsed the relay's permission keys"
        assert defined == shown, (
            f"dashboard is out of step: missing {sorted(defined - shown)}, "
            f"stale {sorted(shown - defined)}"
        )
