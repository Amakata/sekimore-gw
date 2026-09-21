# sekimore-relay

*[日本語版](README.ja.md)*

A relay that brokers an AI agent's git (SSH) and GitHub API traffic under a per-project policy.
It ships inside the sekimore-gw image and only starts when `config.yml` contains `handler: github`.
Without that, nothing changes.

- Changelog: [CHANGELOG.md](CHANGELOG.md)

## The big picture

```
  dev (the AI)                  sekimore-gw                      upstream
  ============                  ===========                      ========

  git clone / push       ─DNS→  :22  SSH                  ─ssh→   GitHub
  git@github.com:Org/Repo        · authenticates the disposable key
                                 · is this repo in the project?
                                 · refs/for/<base> becomes a branch + PR
                                                    uses: the operator's ssh-agent

  sekimore pr create     ─HTTP→  :8420  REST API          ─API→   GitHub
  sekimore ci log                · validates the skm_ project token
                                 · is this resource × action allowed?
                                                    uses: the device flow token

  https://github.com/…   ─DNS→   :443  TCP passthrough    ─TCP→   GitHub
                                 · TLS is not terminated; bytes are counted
                                 · the upload cap applies
```

DNS is what puts the relay in the path: the gateway answers those domains with its own
address, and the real address never enters the firewall's allowlist. So nothing reaches
the upstream except through one of the three lanes above.

The agent holds exactly three things, and none of them work against the upstream:

- a disposable SSH key (to authenticate to the relay)
- a signing key reserved for the AI (commit signatures)
- a project token, `skm_…` (for the relay's API)

The upstream credentials — the operator's ssh-agent and the device flow token — never leave sekimore-gw.

## Setup (operator)

### 1. Turn the relay on

Add this to `config.yml` (mounted at `/etc/sekimore/config.yml`). The minimal form is:

```yaml
domain_handlers:
  github.com: { handler: github }

relay:
  project:
    name: case-a
    permissions: [pr:create, pr:read, ci:read]
    repos:
      - { name: Org/Repo, mode: read-write, bases: [main] }
```

`git-relay` was this handler's original name and is still accepted, so a config that already works needs no edit.

See "Configuration reference" for what each key means and a fuller example.
An unknown key under `relay:` is an error, so a typo can never loosen a permission.

### 2. Hand the operator's ssh-agent to the relay

The relay authenticates to the upstream git with the operator's ssh-agent. The keys never leave the host.

```yaml
# the sekimore-gw service in docker-compose.yml
    volumes:
      - ${SEKIMORE_AGENT_SOCK:-/run/host-services/ssh-auth.sock}:/ssh-agent/agent.sock:ro
    environment:
      - SSH_AUTH_SOCK=/ssh-agent/agent.sock
```

- Docker Desktop (Mac): the defaults just work. Check that `ssh-add -l` on the Mac lists your keys.
- Vagrant VM: put the socket at a fixed path and point `SEKIMORE_AGENT_SOCK` at it.
  For example: `ssh -N -o StreamLocalBindUnlink=yes -R /home/vagrant/.ssh-agent/agent.sock:$SSH_AUTH_SOCK <vm>`

### 3. Restart and check

Changes to `domain_handlers` and `relay` only take effect when the container is recreated. A hot reload warns and keeps the old values.

```bash
docker compose up -d --force-recreate sekimore-gw      # with Dev Containers: mise run gw:recreate
docker compose exec sekimore-gw sekimore-relay check   # policy and state (agent / known_hosts / token / keys)
```

### 4. Authenticate to the upstream (once)

```bash
docker compose exec sekimore-gw sekimore-relay login   # with Dev Containers: mise run gw:login
#   Open: https://github.com/login/device
#   Code: XXXX-XXXX          ← approve it in the browser
```

- The token is stored in `/data/relay/upstream_token` (0600). The upstream's SSH host keys are added to known_hosts at the same time.
- With more than one upstream, run it per upstream with `--upstream <domain>` (same for `logout` and `whoami`).
- `sekimore-relay whoami` shows which GitHub identity the relay acts as.

The device flow token carries the `repo` scope. GitHub's own authorization gives you nothing here — `repos` and `permissions` are the only barrier.
GitHub's audit log cannot tell the agent's actions from a human's, so the relay's `/data/relay/audit.jsonl` is the only record that can.

## Agent-side setup (inside the dev container)

`agent-setup.sh` (in sgw-devcontainer-base, `/usr/local/bin/sekimore-agent-setup.sh`, run from postStartCommand on every start) does all of this automatically once it finds the relay.

- Generates a disposable authentication key `~/.ssh/sekimore/id_ed25519` and a signing key `~/.ssh/sekimore/signing_ed25519` (reusing them if they exist).
- Registers the public keys with `POST /bootstrap` and receives a project token. It does not reissue while a valid token exists.
- Writes the connection details to `/etc/sekimore-agent/env` (0600). The `sekimore` wrapper reads that file and renews the token automatically when it expires.
- Writes a `Host` block in `~/.ssh/config` and a known_hosts entry per upstream.
- Points commit signing at the AI's own key. Register that signing key's public half on GitHub as a "Signing Key" by hand — it is printed in the log.
- Installs the agent-facing usage guide (`sekimore guide`) as a Claude Code skill and in Codex's `AGENTS.md`.

Environment variables for tuning:

| Variable | Meaning |
|---|---|
| `SEKIMORE_BOOTSTRAP=manual` | The operator registers the key and issues the token (`add-key` and `token`) |
| `SEKIMORE_PROJECT` / `SEKIMORE_SIGNING_KEY_COMMENT` | The signing key's comment (its Title when registered on GitHub) |
| `SEKIMORE_AGENT_USER` / `SEKIMORE_KEY_DIR` / `SEKIMORE_AGENT_ENV_FILE` | Target user and where things are stored |

## Everyday use (agent)

```bash
git clone git@github.com:Org/Repo.git           # the URL is unchanged; the relay brokers it transparently
git push origin HEAD:refs/for/main              # pushes to sekimore/main-<sha7> and opens a PR (base=main)
git push origin HEAD:refs/heads/sekimore/x      # a direct push inside your own namespace, sekimore/*

sekimore whoami                                 # your permissions and repos
sekimore pr create --head sekimore/x --base main --title T --body="…"
sekimore pr status --number 12                  # the PR's CI checks (--json for machine-readable output)
sekimore pr merge --number 12 --method squash --delete-branch
sekimore pr update --number 12 --title T         # --base is re-checked against bases
sekimore pr reopen --number 12                   # issue reopen too; same permission as closing
sekimore ci runs --ref v0.2.0                   # workflow runs for a tag / branch / SHA
sekimore ci jobs --number 12                    # every job across the PR's runs (shows failures and job_id)
sekimore ci log --number 12                     # a failed job's log, from the end. --before / --window to go back
sekimore issue create --title T --labels bug    # labels also need issue:label
sekimore release create --tag v0.2.6            # after the tag is pushed; GitHub writes the notes
sekimore release view --tag v0.2.6              # the release for one tag
sekimore release list --limit 10                # the most recent releases, newest first
sekimore release edit --tag v0.2.6 --draft false # publish a draft (needs release:publish)
sekimore issue unlabel --number 5 --labels bug   # issue unassign is the same shape
sekimore ci rerun --run-id 123 [--all]           # ci cancel --run-id 123. Both need ci:rerun
```

Run `sekimore guide` to print the usage guide written for AI agents (embedded in the CLI; the sources of truth are `relay/share/agent-guide.en.md` and `agent-guide.ja.md`).
agent-setup installs the same text as a Claude Code skill (`~/.claude/skills/sekimore-relay/SKILL.md`) and as a marked block in Codex CLI's `~/.codex/AGENTS.md`,
so those tools pick it up on their own. For anything else, put the output of `sekimore guide` wherever that tool expects it. `SEKIMORE_AGENT_INSTRUCTIONS=none` disables it, and you can name just `claude` or just `codex`.

`sekimore` is a wrapper around `sekimore-relay agent`. Name a repo with `--repo Org/Repo`, or `host/Org/Repo` when there is more than one upstream.
When the value of `--body` starts with `-`, write it as `--body="…"`.

Denied by default: repositories outside the project, pushes to a read-only repo, `refs/for` against a base that is not in `bases`, direct pushes outside `sekimore/*`, tags, deletions, and any API action you have not allowed. The reason goes to stderr as `sekimore: …`.

## Configuration reference

### `domain_handlers.<domain>`

Keys are exact FQDN matches. Listing `github` more than once gives you more than one upstream.
`git-relay` is the original name of the `github` handler and stays accepted, so existing configs keep working.

| Key | Default | Meaning |
|---|---|---|
| `handler` | `splice` | `github` makes the relay handle the domain (the SSH git and the GitHub API). `https-relay` passes only 443 through the relay's passthrough (for destinations you want an upload cap on). `deny` rejects, `splice` behaves as before |
| `ssh_port` | the port from `relay.ssh_listen` | The relay's SSH port. Required for the second and later upstreams |
| `upstream` | the domain name | The real upstream host |
| `upstream_ssh_port` | `relay.upstream_ssh_port` | The upstream's SSH port |
| `ssh_options` | `[]` | Passed to the upstream ssh as `-o` (`ProxyJump=bastion`, for example). Enforced options cannot be overridden |
| `api_base` / `graphql_base` | derived from `upstream` | Where the GitHub API lives. Use it when you point `upstream` somewhere else |
| `oauth_client_id` | `relay.oauth_client_id` | The device flow OAuth app (different on GHES) |
| `default` | `false` | Make this the default upstream. If omitted, the one without an `ssh_port` is the default |
| `max_upload_bytes` | `relay.https_max_upload_bytes` | Per-connection cap on what dev may send upstream through the 443 passthrough. `-1` means unlimited; `0` is not allowed |

### `relay`

| Key | Default | Meaning |
|---|---|---|
| `ssh_listen` / `api_listen` / `https_listen` | `0.0.0.0:22` / `0.0.0.0:8420` / `0.0.0.0:443` | Listen addresses |
| `https` | `passthrough` | What to do with 443. `reject` drops the connection immediately |
| `https_max_upload_bytes` | `1048576` | Default upload cap for the 443 passthrough, in bytes. `-1` means unlimited. A connection that exceeds it is cut and audited as `https_upload_capped` |
| `state_dir` | `/data/relay` | Where state files live |
| `store.unlock` | `prompt` | How the secret store is unlocked. `prompt` means a person runs `mise run gw:unlock` after every restart and the passphrase is nowhere at rest. `file` (`path:`) and `env` (`var:`) read it instead — **for developing this project**, where the gateway is recreated many times an hour; they put the passphrase at rest and the relay says so in the log at start-up. Never set `env` through `.devcontainer/.env`: the agent can write that file |
| `token_ttl` | `12h` | How long a project token lives |
| `bootstrap` | `auto` | Whether `POST /bootstrap` is allowed. With `manual`, the operator registers keys |
| `ssh_options` | `[]` | `-o` options shared by all upstreams |
| `ssh_config` | none | A file passed to the upstream ssh as `-F` (advanced) |
| `upstream` / `upstream_ssh_port` / `api_base` / `graphql_base` / `oauth_client_id` | | For the default upstream. Setting these on the handler is the newer style |
| `limits` | | Session counts and timeouts |
| `project` | required | The project (below) |

### `relay.project`

| Key | Default | Meaning |
|---|---|---|
| `name` | required | The project name. It appears in tokens and logs |
| `permissions` | `[]` | The project's default permissions. Either `[…]` or `{allow, deny}` |
| `push` | `["sekimore/*"]` | Branch globs that may be pushed to directly |
| `tags` | `[]` | Tag globs that may be pushed. Empty means denied |
| `delete` | `false` | Deleting branches and tags, and moving a tag that already exists upstream. Delete-and-recreate and a forced update leave the same result, so they share one authority. Creating a tag that is not there yet only needs `tags` |
| `delete_merged_branch` | `false` | Whether `pr merge --delete-branch` may remove the branch it just merged. Only that branch, so it is not the same authority as `delete`. Leave it off where the forge already deletes merged branches itself |
| `boards` | `[]` | The Projects v2 boards this project may touch, written the way the URL reads: `{ org: acme, number: 3 }` for `github.com/orgs/acme/projects/3`, or `{ user: someone, number: 1 }`. Empty refuses every Projects operation |
| `repos` | `[]` | Repositories. `Org/Repo` means the default upstream; `host/Org/Repo` names one explicitly |
| `upstreams.<domain>` | | A per-upstream layer: `permissions` (a delta), `push` / `tags` / `delete` (that upstream's defaults), and `repos` |

### `repos[]`

| Key | Default | Meaning |
|---|---|---|
| `name` | required | `Org/Repo` (no host needed inside `upstreams.<domain>.repos`) |
| `mode` | required | `read-only` or `read-write`. read-only blocks every write |
| `bases` | all | Branches allowed for `refs/for/<base>` and as a PR base |
| `push` / `tags` / `delete` | the layer above | Override for this repo only |
| `permissions` | no delta | `{allow, deny}` to add or remove. A plain list adds to allow |

### How permissions resolve

- Effective permissions = (project allow ∪ upstream allow ∪ repo allow) − (project deny ∪ upstream deny ∪ repo deny). A deny wins at any layer.
- `push` / `tags` / `delete` are overridden in the order project → upstream → repo. Globs support `*` and `?`.
- There are 23 permission keys: `pr:create` `pr:read` `pr:comment` `pr:review` `pr:request_review` `pr:merge` `pr:close`, `issue:create` `issue:read` `issue:comment` `issue:close` `issue:label` `issue:assign`, `project:read` `project:add_item` `project:update_item`, `repo:read`, `ci:read` `ci:rerun`, `release:create` `release:read` `release:publish`, `search:read`.
- `pr:read` covers the state, the CI checks, the description and the comments. `issue:read` is separate, so an agent can file bugs without reading a private tracker. `search:read` is its own resource because a search is not addressed to one repository.
- `pr:review` submits a review; `pr:request_review` asks someone else for one. They are separate because one records an opinion and the other notifies a person.
- `ci:rerun` re-runs and cancels workflow runs. It is not part of `ci:read`, because a re-run spends Actions minutes and executes workflow code with the repository's secrets.
- `release:publish` takes a release out of draft. `release:create --draft` exists so that publishing can be left to a human, so folding it into `release:create` would erase that line; editing a release that stays a draft needs only `release:create`.
- Closing and reopening are one permission (`pr:close` / `issue:close`): reopening undoes a close rather than adding a power. Adding and removing a label or an assignee are likewise one (`issue:label` / `issue:assign`), and editing a pull request's title or body is `pr:create` — except that a new base is re-checked against the repository's `bases`.
- `repo:read` covers `repo vocabulary`, which lists the labels, assignable people and milestones a repository defines.
- Check the effective values with `sekimore-relay check` or the Relay tab in the Web UI.

### Example: github.com and GHES side by side

```yaml
domain_handlers:
  github.com: { handler: github }                       # the default upstream (ssh_port omitted)
  ghe.example.com:
    handler: github
    ssh_port: 2222                                      # the second and later upstreams need their own port
    ssh_options: [ProxyJump=bastion.example.com]        # if it sits behind a bastion

relay:
  project:
    name: case-a
    permissions: [pr:read, ci:read]                     # shared by every upstream
    upstreams:
      github.com:
        permissions: { allow: [pr:create, pr:merge] }
        tags: ["v*"]
        repos:
          - { name: Org/App, mode: read-write, bases: [main] }
      ghe.example.com:
        permissions: { allow: [pr:create], deny: [pr:merge] }   # no merging on GHES
        repos:
          - { name: Corp/Internal, mode: read-write, bases: [main] }
```

### Releases (0.2.6)

`release:create` and `release:read` are denied by default like every other permission, so list them in `permissions`
where you want them. The device flow token already carries the `repo` scope, so nothing has to be re-authenticated.

```bash
git push origin v0.2.6                                   # the tag has to exist upstream first
sekimore release create --tag v0.2.6                     # GitHub writes the notes from the merged PRs
sekimore release create --tag v0.2.6 --notes-file NOTES.md --draft
sekimore release view --tag v0.2.6
sekimore release list --limit 10
```

- The tag must already be upstream, so this runs after the tag push. GitHub answers 422 when the tag does not exist.
- Without a body the relay asks for `generate_release_notes`, and GitHub composes it from the pull requests merged
  since the previous tag. That is the usual path: nothing to write by hand.
- `--notes` or `--notes-file` is used as the body instead. Add `--generate-notes` and GitHub appends its generated
  notes to what you wrote.
- `--title` defaults to the tag, so a release is never left untitled. `--prerelease` marks it as one.
- `--draft` creates the release unpublished and leaves publishing to a human. The default is published.
- `sekimore release edit --tag v0.2.6 --draft false` publishes that draft, and needs `release:publish`.
  Editing a release that stays a draft (`--title`, `--notes`, `--prerelease`) needs only `release:create`.

### Exfiltration controls: the 443 upload cap and `https-relay`

The relay never lets the AI use the operator's credentials, but an HTTPS push with someone else's credentials pasted into a prompt is indistinguishable from normal traffic unless you look inside the TLS.
So the 443 passthrough caps how many bytes dev may send upstream (1 MiB by default; downloads are not counted).
Ordinary GETs and API calls send far less than that, and only large uploads such as a `git push` are stopped.

```yaml
domain_handlers:
  github.com: { handler: github, max_upload_bytes: 262144 }      # 256 KiB. HTTPS push is unnecessary — SSH goes through the relay
  ghcr.io:    { handler: https-relay, max_upload_bytes: -1 }     # unlimited where you push your own images
  registry-1.docker.io: { handler: https-relay }                 # use the default (relay.https_max_upload_bytes)
relay:
  https_max_upload_bytes: 1048576
network:
  allowed_ports: [80, 443]      # destination ports allowed through to permitted domains (a sekimore-gw setting; blocks things like SSH to a bare IP)
```

- A `https-relay` domain resolves to the relay through DNS, and only 443 goes through the relay's passthrough. Nothing else reaches it.
- A connection over the cap is cut and leaves `https_upload_capped` in the audit log. The Relay tab marks connections that sent 1 MiB or more with LARGE UPLOAD and shows 24-hour counts.
- Domains left in `allow_domains` bypass the relay entirely and get no cap. Move only the ones you want capped over to a handler.

How multiple upstreams work: an SSH exec carries no host name, so the relay listens on a separate port per upstream and picks the upstream from the port the connection arrived on.
agent-setup writes a `Host` and `Port` per upstream into `~/.ssh/config`, so the agent's URLs stay the same.
On 443 the upstream comes from the TLS SNI. The relay's ssh does not read the host's `~/.ssh/config`, so bastions and proxies belong in `ssh_options`.
Add a bastion's host key with `sekimore-relay keyscan bastion.example.com --upstream ghe.example.com`.

## Language (0.2.4)

The CLI's strings live in `relay/locales/en.json` and `relay/locales/ja.json`, embedded in the binary.
The language comes from `SEKIMORE_LANG`, then `LC_ALL`, `LC_MESSAGES`, `LANG`: `ja*` selects Japanese, anything else English (English is the default).
A key missing from a dictionary falls back to English, and then to the key name.

```bash
sekimore-relay check                     # English (default)
SEKIMORE_LANG=ja sekimore-relay check    # Japanese
sekimore guide --lang ja                 # print just the guide in Japanese
```

This covers `--help`, operator-facing output, and `sekimore guide`.
The guide takes `--lang en|ja`, and its sources of truth are `relay/share/agent-guide.en.md` and `relay/share/agent-guide.ja.md`.
Denial reasons (`sekimore: …`) and the audit log `audit.jsonl` stay English on purpose, so that tooling and agents can match on them.

## Operations (operator)

The Relay tab in the Web UI (http://localhost:8090 on the host) shows the configuration, permissions, tokens, access history and blocked attempts (read-only).
Under Dev Containers you also get `mise run gw:tokens` / `gw:revoke-project` / `gw:audit` / `gw -- <args>`.

| Command | Purpose |
|---|---|
| `sekimore-relay check` | List the policy and current state |
| `sekimore-relay tokens` | Issued tokens (label / expiry / use count / state) |
| `sekimore-relay revoke --label skm_xxxxxxxx` | Revoke one |
| `sekimore-relay revoke-project` | Revoke every token for the project (when the engagement ends) |
| `sekimore-relay bootstrap disable` / `enable` | Kill switch for automatic registration |
| `sekimore-relay add-key "ssh-ed25519 AAAA…"` | Register a public key by hand |
| `sekimore-relay keyscan <host> [--port N] [--upstream <domain>]` | Add an upstream's or bastion's host key to known_hosts (prints the fingerprint) |
| `sekimore-relay login` / `logout` / `whoami` `[--upstream <domain>]` | Upstream tokens |
| `tail -f /data/relay/audit.jsonl` | Every action and every denial |

`/data/relay` is the gateway's volume (0700) and is invisible from the AI container.
Re-bootstrapping with the same key revokes the previous token, so one key ever has one valid token.
Token records are swept 7 days after they expire. The permanent record is `audit.jsonl`.

## Troubleshooting

| Symptom | What it means | What to do |
|---|---|---|
| `SSH_AUTH_SOCK is not set in the gateway container` | The agent socket never reached the relay | Check the mount and environment from step 2, and `ssh-add -l` on the Mac |
| `ssh-agent socket … does not exist` / `cannot connect` | Forwarding dropped, or a permission problem | Re-establish the forward. On EACCES, check who owns the socket |
| `known_hosts … has no entry for <host>` | The upstream's host key is missing | `sekimore-relay login` or `sekimore-relay keyscan <host>` |
| `repository "X" is not in project "P"` | Outside the project | Add it to `repos`. If the denial was intended, do nothing |
| `push to refs/heads/main is not allowed` | A direct push outside the namespace | Use `refs/for/main` to open a PR, or add a glob to `push` if you really need it |
| `tag is not allowed for this repository` | Tag pushes are denied by default | Add a glob to `tags` on that repo or upstream |
| `Permission denied (publickey)` (from the relay) | The agent's key is not registered | `sudo sekimore-agent-setup.sh`, or `add-key` by the operator. Check for `bootstrap.disabled` |
| `! [remote rejected] … (sekimore: …)` | A push the policy denied | Follow what the message says |
| `denied: token expired at …` | The project token expired | The `sekimore` wrapper renews it automatically. On an older environment, run `sudo sekimore-agent-setup.sh` |
| `no upstream token … run sekimore-relay login` | The device flow was never run, or you logged out | `sekimore-relay login` |
| `git ls-remote` hangs silently | DNS points at the relay but INPUT is dropping it | Look for `--dport 22` in `iptables-legacy -S INPUT`. If it is missing, the relay did not start |
| `https://github.com/…` fails | `https: reject`, or the upstream is unreachable | Put it back to the default `passthrough`. Check `https_failed` in the audit log |
| `could not read Username` on HTTPS git | HTTPS authentication is blocked on purpose, so the operator's credentials cannot bypass the relay | Use SSH: `git@github.com:` |
| post-create keeps saying the ssh-agent is being forwarded | `code` on macOS inherits launchd's environment | Quit VS Code completely and run `mise run vscode` |

## Development

```bash
mise use rust@1.89                                  # or rustup
cargo test --features test-hooks                    # the e2e tests need git and ssh (CI sets SEKIMORE_E2E_REQUIRED=1)
cargo clippy --all-targets --features test-hooks -- -D warnings
cargo fmt --check
cargo audit                                         # every ignore in .cargo/audit.toml has a reason
cargo tree -i aws-lc-rs; cargo tree -i openssl-sys  # neither should be present
```

Running `mise run ci` at the root of sekimore-gw runs the Rust and Python lints and tests in parallel.
The `test-hooks` feature enables `LocalGitUpstream` (`git receive-pack` against a local bare repo). It is not part of the image build.

## Building the image

The `relay-builder` stage of `sekimore-gw/Dockerfile` produces a static musl binary with `cargo-zigbuild` (CI uses a native runner per architecture).
It does not depend on a glibc generation, so `COPY --from` into the devcontainer base image is all it takes.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).
