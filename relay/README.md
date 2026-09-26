# sekimore-relay

*[日本語版](README.ja.md)*

sekimore-relay brokers an AI agent's git (SSH) and GitHub API traffic under a per-project policy.
It ships in the sekimore-gw image and starts only when `config.yml` contains `handler: github`.
Without that setting, the gateway behaves exactly as it does without the relay.

- Changelog: [CHANGELOG.md](CHANGELOG.md)

## Overview

```
  dev (the AI)                  sekimore-gw                      upstream
  ============                  ===========                      ========

  git clone / push       ─DNS→  :22  SSH                  ─ssh→   GitHub
  git@github.com:Org/Repo        · authenticates the disposable key
                                 · is this repo in the project?
                                 · refs/for/<base> and refs/pr/<branch> become a branch and a PR
                                                    uses: the operator's ssh-agent

  sekimore pr create     ─HTTP→  :8420  REST API          ─API→   GitHub
  sekimore ci log                · validates the skm_ project token
                                 · is this resource × action allowed?
                                                    uses: the device flow token

  https://github.com/…   ─DNS→   :443  TCP passthrough    ─TCP→   GitHub
                                 · TLS is not terminated; bytes are counted
                                 · the upload cap applies
```

The relay sits in the path because of DNS. The gateway resolves the relayed domains to its own
address, and the real upstream address never enters the firewall's allowlist. As a result, traffic
reaches the upstream only through one of the three paths above.

The agent holds exactly three credentials, and none of them is valid against the upstream:

- A disposable SSH key (for authenticating to the relay)
- A commit-signing credential reserved for the AI: a filtered agent socket when `relay.signing_key` is set, otherwise a signing key generated in the dev container
- A project token, `skm_…` (for the relay's API)

The upstream credentials — the operator's ssh-agent and the device flow token — never leave sekimore-gw.

## Setup (operator)

### 1. Enable the relay

Add the following to `config.yml` (mounted at `/etc/sekimore/config.yml`). This is the minimal configuration:

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

`git-relay` is the original name of this handler and is still accepted, so an existing working configuration needs no changes.

See [Configuration reference](#configuration-reference) for the meaning of each key and a fuller example.
An unknown key under `relay:` is an error, so a typo cannot loosen a permission.

### 2. Pass the operator's ssh-agent to the relay

The relay authenticates to the upstream git server with the operator's ssh-agent. The keys never leave the host.

```yaml
# the sekimore-gw service in docker-compose.yml
    volumes:
      - ${SEKIMORE_AGENT_SOCK:-/run/host-services/ssh-auth.sock}:/ssh-agent/agent.sock:ro
    environment:
      - SSH_AUTH_SOCK=/ssh-agent/agent.sock
```

- Docker Desktop (Mac): the default values work without changes. Check that `ssh-add -l` on the Mac lists your keys.
- Vagrant VM: create the socket at a fixed path and set `SEKIMORE_AGENT_SOCK` to that path.
  For example: `ssh -N -o StreamLocalBindUnlink=yes -R /home/vagrant/.ssh-agent/agent.sock:$SSH_AUTH_SOCK <vm>`

### 3. Restart and verify

Changes to `domain_handlers` and `relay` take effect only when the container is recreated. A hot reload logs a warning and keeps the old values.

```bash
docker compose up -d --force-recreate sekimore-gw      # with Dev Containers: mise run gw:recreate
docker compose exec sekimore-gw sekimore-relay check   # policy and state (agent / known_hosts / token / keys)
```

### 4. Authenticate to the upstream (first time only)

```bash
docker compose exec sekimore-gw sekimore-relay login   # with Dev Containers: mise run gw:login
#   Open: https://github.com/login/device
#   Code: XXXX-XXXX          ← approve the code in the browser
```

- The token is sealed in the secret store (0.2.18), so the gateway must be unlocked (`mise run gw:unlock`) before a login can store the token. If an older version left a `/data/relay/upstream_token` file, the relay moves the token into the store and deletes the file the first time it reads the token. The login also adds the upstream's SSH host keys to known_hosts.
- With more than one upstream, run the command once per upstream with `--upstream <domain>`. The same applies to `logout` and `whoami`.
- `sekimore-relay whoami` shows which GitHub identity the relay acts as.

The device flow token has the `repo` scope. GitHub's own authorization therefore provides no restriction here, and `repos` and `permissions` are the only barrier.
GitHub's audit log cannot distinguish the agent's actions from a human's, so the relay's `/data/relay/audit.jsonl` is the only record that makes this distinction.

## Agent-side setup (inside the dev container)

`agent-setup.sh` (installed as `/usr/local/bin/sekimore-agent-setup.sh` in sgw-devcontainer-base and run by postStartCommand on every start) performs the following steps automatically when it detects the relay:

- Generates a disposable authentication key, `~/.ssh/sekimore/id_ed25519`, or reuses the existing one.
- Registers the public key with `POST /bootstrap` and receives a project token. While a valid token exists, it does not request a new one.
- Writes the connection details to `/etc/sekimore-agent/env` (0600). `sgw-agent` reads this file and renews the token automatically when it expires (`sekimore`, its former name, execs it).
- Writes a `Host` block to `~/.ssh/config` and a known_hosts entry for each upstream.
- Configures commit signing. `relay.signing_key` (see below) determines which key is used.
- Installs the usage guide for AI agents (`sgw-agent guide`) as a Claude Code skill and in Codex's `AGENTS.md`.

Environment variables for tuning:

| Variable | Meaning |
|---|---|
| `SEKIMORE_BOOTSTRAP=manual` | The operator registers the key and issues the token (`add-key` and `token`). |
| `SEKIMORE_PROJECT` / `SEKIMORE_SIGNING_KEY_COMMENT` | The signing key's comment (the Title when the key is registered on GitHub) |
| `SEKIMORE_AGENT_USER` / `SEKIMORE_KEY_DIR` / `SEKIMORE_AGENT_ENV_FILE` | The target user and the storage locations |

### Signing key (0.2.29, #59)

The authentication key above is disposable by design. It grants access, so a short lifetime is a
safeguard. A signing key is the opposite case. It grants no access, a person registers it with
GitHub by hand, and deleting it removes the Verified badge from every commit it has signed. Losing
a signing key is therefore not a matter of generating a new one; it is a loss of data. When the key
was generated per container, every wiped volume produced a new key. Each new key had to be
registered by hand, and none of the old keys could be removed.

With `relay.signing_key` set, there is **one key per person** instead. The key is stored in the
host ssh-agent that is already mounted into the gateway, and it is registered with GitHub once.
The relay offers the dev container a **filtered** agent socket on a shared volume:

| Request | Response |
|---|---|
| `REQUEST_IDENTITIES` | Only the key with the configured fingerprint |
| `SIGN_REQUEST` | Forwarded only when the fingerprint matches **and** the data is an SSHSIG blob with the namespace `git` |
| add / remove / lock / extension | `SSH_AGENT_FAILURE` |

A git signature covers `"SSHSIG" ++ namespace ++ …`. An SSH *authentication* signature covers a
different structure that starts with a length-prefixed session ID, so it never begins with the
6-byte `SSHSIG` magic. The socket therefore cannot authenticate to any server, including the
relay's own sshd, even if the same key is also registered as an authentication key. The
operator's other keys can be in the same agent; the fingerprint filter hides them. The relay
audits refusals as `signing_agent_refused` and successful signatures as `signing_agent_signed`.

The socket is created with mode 0600 and owned by `socket_uid`. The relay sets both through a file
descriptor rather than by path. The volume is shared and the dev container has sudo, so a `chmod`
that resolved the path again could be redirected to a file in the gateway.

The dev container needs no sekimore-specific command; a plain `git commit` is enough.
`agent-setup.sh` writes the public key to `~/.ssh/sekimore/signing.pub`, sets `user.signingkey`
to that file, and writes `SSH_AUTH_SOCK` to `/etc/sekimore-agent/env`.

```yaml
# config.yml
relay:
  signing_key:
    fingerprint: "SHA256:…"    # ssh-keygen -lf <key>.pub; use a key other than the operator's own signing key
```

```yaml
# docker-compose.yml: mount the socket's volume in both services
services:
  sekimore-gw:
    volumes: [sekimore-signing:/run/sekimore]
  dev:
    volumes: [sekimore-signing:/run/sekimore]
```

`sekimore-relay check` prints the fingerprint and whether the host agent actually holds that key.
If the agent does not hold it, `agent-setup.sh` sets `commit.gpgsign false` and reports this. It
does not substitute a key that nobody has registered.

### `signing: required` makes one upstream API query

A pack contains only the objects that the upstream does not have. The point where a push's history
leaves the pack is therefore expected to be history that the upstream already has. However, a
commit hidden behind a delta whose base object exists upstream looks exactly the same from inside
the pack. A hand-crafted pack of that shape would carry an unsigned commit past the check.
`git push` never builds such a pack (`pack-objects` uses only trees and blobs as thin bases), but
the client here is an AI agent.

At that boundary, the relay therefore sends `GET /repos/{repo}/git/commits/{sha}`. It makes one or
two calls per push regardless of how many blob deltas the pack contains, and each call stays within
the authorization that the push has already passed. If the relay cannot get an answer, it refuses
the push. **`required` therefore requires the gateway to be unlocked (`mise run gw:unlock`) and
logged in**, and the denial message says so when either is missing.

Without `relay.signing_key`, the previous behavior applies. `agent-setup.sh` generates
`~/.ssh/sekimore/signing_ed25519` in the dev container, and a person must register its public key
on GitHub as a "Signing Key" by hand. The public key is printed in the log.

## Everyday use (agent)

```bash
git clone git@github.com:Org/Repo.git           # the URL is unchanged; the relay brokers the connection transparently
git push origin HEAD:refs/pr/feature/login      # 0.3.0: pushes to feature/login and opens a PR (base = the default branch)
git push origin HEAD:refs/for/main              # pushes to sekimore/main-<sha7> and opens a PR (base=main)
git push origin HEAD:refs/heads/sekimore/x      # a direct push to a branch that `push` allows (default sekimore/*)

sekimore whoami                                 # your permissions and repos
sekimore pr create --head sekimore/x --base main --title T --body="…"
sekimore pr status --number 12                  # the PR's CI checks (--json for machine-readable output)
sekimore pr merge --number 12 --method squash --delete-branch
sekimore pr update --number 12 --title T         # --base is checked again against bases
sekimore pr reopen --number 12                   # issue reopen works the same way; it needs the same permission as closing
sekimore ci runs --ref v0.2.0                   # workflow runs for a tag / branch / SHA
sekimore ci jobs --number 12                    # every job across the PR's runs (shows failures and job_id)
sekimore ci log --number 12                     # a failed job's log, from the end; --before / --window to page back
sekimore issue create --title T --labels bug    # labels also require issue:label
sekimore release create --tag v0.2.6            # run after the tag is pushed; GitHub writes the notes
sekimore release view --tag v0.2.6              # the release for one tag
sekimore release list --limit 10                # the most recent releases, newest first
sekimore release edit --tag v0.2.6 --draft false # publishes a draft (requires release:publish)
sekimore issue unlabel --number 5 --labels bug   # issue unassign takes the same form
sekimore ci rerun --run-id 123 [--all]           # also: ci cancel --run-id 123; both require ci:rerun
```

`sgw-agent guide` prints the usage guide for AI agents. The guide is embedded in the CLI, and its sources are `relay/share/agent-guide.en.md` and `agent-guide.ja.md`.
agent-setup installs the same text as a Claude Code skill (`~/.claude/skills/sekimore-relay/SKILL.md`) and as a marked block in Codex CLI's `~/.codex/AGENTS.md`,
so these tools read it automatically. For other tools, place the output of `sgw-agent guide` in the location that the tool's conventions specify. `SEKIMORE_AGENT_INSTRUCTIONS=none` disables the installation, and `claude` or `codex` limits it to one tool.

`sgw-agent` is `sekimore-relay agent` with the env file and the token refresh built in; `sekimore` is its former name and still works. Specify a repository with `--repo Org/Repo`. When there is more than one upstream, you can also write `host/Org/Repo`.
If the value of `--body` starts with `-`, write it as `--body="…"`.

The following are denied by default: repositories outside the project, pushes to a read-only repository, `refs/for` to a base that is not in `bases`, direct pushes and `refs/pr/` branch names outside `push`, tags, deletions, and any API action that the configuration does not allow. The reason is printed to stderr as `sgw-agent: …`.

For each read-write repository, `sgw-agent whoami` prints the branch names that the repository accepts (`push`), the bases it allows, and the branch and base that each ref form resolves to. The agent can therefore check these rules before its first push.

## Configuration reference

### `domain_handlers.<domain>`

Each key is a fully qualified domain name and must match exactly. Configuring `github` for more than one domain creates more than one upstream.
`git-relay` is the original name of the `github` handler and is still accepted, so existing configurations continue to work.

| Key | Default | Meaning |
|---|---|---|
| `handler` | `splice` | `github` routes the domain to the relay (SSH git and the GitHub API). `https-relay` routes only port 443 through the relay's passthrough (for destinations that need an upload cap). `deny` rejects the domain, and `splice` keeps the behavior without the relay. |
| `ssh_port` | the port of `relay.ssh_listen` | The relay's SSH port. Required for the second and later upstreams. |
| `upstream` | the domain name | The actual upstream host |
| `upstream_ssh_port` | `relay.upstream_ssh_port` | The upstream's SSH port |
| `ssh_options` | `[]` | Options passed to the upstream ssh with `-o` (for example, `ProxyJump=bastion`). These cannot override the enforced options. |
| `api_base` / `graphql_base` | derived from `upstream` | The GitHub API endpoints. Set them when `upstream` points to a different host. |
| `oauth_client_id` | `relay.oauth_client_id` | The OAuth app for the device flow (a different app on GHES) |
| `default` | `false` | Makes this domain the default upstream. If no domain sets it, the one without `ssh_port` is the default. |
| `max_upload_bytes` | `relay.https_max_upload_bytes` | The per-connection limit on bytes that the dev container can send upstream through the 443 passthrough. `-1` means unlimited; `0` is not allowed. |

### `relay`

| Key | Default | Meaning |
|---|---|---|
| `ssh_listen` / `api_listen` / `https_listen` | `0.0.0.0:22` / `0.0.0.0:8420` / `0.0.0.0:443` | Listen addresses |
| `https` | `passthrough` | How port 443 is handled. `reject` closes the connection immediately. |
| `https_max_upload_bytes` | `1048576` | The default upload cap for the 443 passthrough, in bytes. `-1` means unlimited. The relay closes a connection that exceeds the cap and audits it as `https_upload_capped`. |
| `state_dir` | `/data/relay` | The directory for state files |
| `store.unlock` | `prompt` | How the secret store is unlocked. With `prompt`, a person runs `mise run gw:unlock` after every restart, and the passphrase is never stored at rest. `file` (`path:`) and `env` (`var:`) read the passphrase instead. They are **for developing sekimore-gw itself**, where the gateway is recreated many times an hour. They store the passphrase at rest, and the relay logs a warning about this at startup. Never set `env` through `.devcontainer/.env`, because the agent can write to that file. |
| `token_ttl` | `12h` | The lifetime of a project token |
| `bootstrap` | `auto` | Whether `POST /bootstrap` is allowed. With `manual`, the operator registers keys. |
| `ssh_options` | `[]` | `-o` options shared by all upstreams |
| `ssh_config` | none | A file passed to the upstream ssh with `-F` (for advanced use) |
| `upstream` / `upstream_ssh_port` / `api_base` / `graphql_base` / `oauth_client_id` | | Settings for the default upstream. Setting these on the handler is the newer style. |
| `limits` | | Session counts and timeouts |
| `signing_key` | none | 0.2.29 (#59): the key that the dev container signs commits with, offered through a filtered agent socket. Its keys are `source` (`agent`), `fingerprint` (`SHA256:…`), `namespace` (`git`), `timeout` (`15s`), `socket` (`/run/sekimore/signing-agent.sock`), and `socket_uid` (`1000`). If it is not set, the dev container generates its own key (see [Signing key](#signing-key-0229-59)). |
| `project` | required | The project (see below) |

### `relay.project`

| Key | Default | Meaning |
|---|---|---|
| `name` | required | The project name. It appears in tokens and logs. |
| `permissions` | `[]` | The project's default permissions, as either `[…]` or `{allow, deny}`. A permission that no layer allows is denied. The 33 keys are listed under [How permissions are resolved](#how-permissions-are-resolved). |
| `push` | `["sekimore/*"]` | Branch globs that the agent can push to directly |
| `tags` | `[]` | Tag globs that the agent can push. An empty list denies all tag pushes. |
| `delete` | `false` | Whether the agent can delete branches and tags, and move a tag that already exists upstream. Deleting and recreating a tag has the same result as a forced update, so both require the same permission. Creating a tag that does not exist yet requires only `tags`. |
| `delete_merged_branch` | `false` | Whether `pr merge --delete-branch` can delete the branch that it has just merged. This applies only to that branch, so it is a separate permission from `delete`. It is unnecessary when the forge already deletes merged branches automatically. |
| `signing` | `optional` | 0.2.29 (#59): whether a push to a branch can contain an unsigned commit — `required` \| `optional` \| `off`. With `required`, the relay refuses a push to `refs/heads/*`, `refs/for/*` or `refs/pr/*` if any commit in it has no signature. Like `signed_tags`, it checks that a signature is present, not that it is valid. It **uses the upstream API** (see [above](#signing-required-makes-one-upstream-api-query)), so the store must be unlocked and logged in. The default is `optional`, so the behavior of existing projects does not change. It can be overridden per upstream and per repository. |
| `branch` | see below | 0.3.0 (#158): how the relay names the branch that it creates for `refs/for/<base>` |
| `boards` | `[]` | The Projects v2 boards that this project can access, written as they appear in the URL: `{ org: acme, number: 3 }` for `github.com/orgs/acme/projects/3`, or `{ user: someone, number: 1 }`. An empty list denies every Projects operation. |
| `repos` | `[]` | Repositories. `Org/Repo` refers to the default upstream; `host/Org/Repo` names the upstream explicitly. |
| `upstreams.<domain>` | | A per-upstream layer: `permissions` (a delta), `push` / `tags` / `delete` (the defaults for that upstream), and `repos` |

### `repos[]`

| Key | Default | Meaning |
|---|---|---|
| `name` | required | `Org/Repo` (the host is not needed inside `upstreams.<domain>.repos`) |
| `mode` | required | `read-only` or `read-write`. `read-only` blocks every write operation. |
| `bases` | all | The branches allowed for `refs/for/<base>` and as a PR base. If it is omitted, the agent can choose the base. `refs/pr/` requires it to be omitted. |
| `push` / `tags` / `delete` | the value from the layer above | Overrides for this repository only |
| `permissions` | no delta | `{allow, deny}` adds or removes permissions. A plain list adds to `allow`. |

### Branch names (0.3.0, #158)

A project's branches usually follow a naming convention, such as `feature/` for features and `fix/`
for bug fixes. Two settings determine whether the relay can follow that convention.

**The names that the agent can give a branch** are set by `push`, a list of globs. The relay checks
it for a direct push, for `refs/pr/<branch>`, and for the head branch of a pull request:

```yaml
repos:
  - name: Org/Repo
    mode: read-write
    push: ["feature/*", "fix/*", "chore/*"]   # replaces the default sekimore/*
```

**The name that the relay gives a branch** is set by `project.branch`, which applies to `refs/for/<base>`:

```yaml
relay:
  project:
    branch:
      template: "sekimore/{branch}-{sha}"   # the default
      on_exists: reject
```

| Key | Default | Meaning |
|---|---|---|
| `template` | `sekimore/{branch}-{sha}` | The relay substitutes `{branch}`, `{base}` and `{sha}`; `{sha}` is the short SHA. For `refs/for/<base>`, `{branch}` and `{base}` are the same string, because `refs/for/<base>` does not carry a separate branch name. The relay rejects a template with an unknown placeholder, an unbalanced brace, or no placeholder at all when it loads the configuration file. |
| `on_exists` | `reject` | What the relay does when a branch with that name already exists upstream: `reject` or `update`. It also applies to `refs/pr/<branch>`. A template that contains `{sha}` names a branch that only that commit can use, so pushing the same commit again remains idempotent regardless of this setting. |

A project that does not want the string `sekimore` in its history can set `template: "agent/{base}-{sha}"`
or any other pattern.

#### Choosing the ref to push to

| Ref | Branch | Base |
|---|---|---|
| `refs/pr/<branch>` | exactly `<branch>` | the upstream's default branch (requires `bases` to be unset) |
| `refs/for/<base>` | generated from `template` | `<base>` |
| `refs/heads/<branch>` | exactly `<branch>`, with no pull request | — |

`refs/pr/` cannot specify a base, because there is no safe way to encode one. Every character that
git accepts as a separator is also valid inside a branch name, and the characters that git forbids
in a branch name (`:` `^` `~`) are also rejected in a refspec. To open a pull request against a
different base, push without opening one and then run `sgw-agent pr create --head <branch> --base <base>`,
or change the base afterwards with `sgw-agent pr update --base <base>`.

**`refs/pr/` requires `bases` to be unset.** A `refs/pr/` push opens the pull request against the
default branch, and the relay learns the default branch from the API only after the push. In a
repository that lists `bases`, the relay could check the base only after the branch had already
reached the upstream. The relay therefore rejects `refs/pr/` in such a repository before it sends
anything. To use `refs/pr/`, leave `bases` unset. Alternatively, use `refs/for/<base>`, which
specifies the base in the ref and is checked before the push is sent.

### How permissions are resolved

- Effective permissions = (project allow ∪ upstream allow ∪ repo allow) − (project deny ∪ upstream deny ∪ repo deny). A deny takes precedence at any layer.
- `push` / `tags` / `delete` are overridden in the order project → upstream → repo. Globs support `*` and `?`.
- There are 33 permission keys, grouped by resource. `sekimore-relay check` prints the ones that a configuration grants.

  ```
  pr:      create  read  comment  comment_update  comment_delete  review  request_review
           label  assign  close  merge
  issue:   create  read  update  comment  comment_update  comment_delete  label  assign  close
  ci:      read  rerun  dispatch          security: read  dismiss
  release: create  read  publish          project:  read  add_item  update_item
  repo:    read                           search:   read
  ```

- `pr:read` covers the state, the CI checks, the description and the comments. `issue:read` is a separate permission, so an agent can file bugs without being able to read a private tracker. `search:read` is a separate resource because a search is not addressed to a single repository.
- `pr:review` submits a review, and `pr:request_review` requests a review from someone else. They are separate because the first records an opinion and the second notifies a person.
- `ci:rerun` re-runs and cancels workflow runs. It is not part of `ci:read`, because a re-run consumes Actions minutes and executes workflow code that has access to the repository's secrets.
- `release:publish` publishes a draft release. `release create --draft` exists so that publishing can be left to a human; folding publishing into `release:create` would remove that separation. Editing a release that remains a draft requires only `release:create`.
- Closing and reopening share one permission (`pr:close` / `issue:close`), because reopening undoes a close rather than granting a new capability. Likewise, adding and removing a label or an assignee share one permission (`issue:label` / `issue:assign`). Editing a pull request's title or body requires `pr:create`, but a new base is checked again against the repository's `bases`.
- `repo:read` is required for `repo vocabulary`, which lists a repository's labels, assignable users and milestones.
- You can check the effective values with `sekimore-relay check` or in the Relay tab of the Web UI.

### Example: github.com and GHES together

```yaml
domain_handlers:
  github.com: { handler: github }                       # the default upstream (ssh_port omitted)
  ghe.example.com:
    handler: github
    ssh_port: 2222                                      # the second and later upstreams need their own port
    ssh_options: [ProxyJump=bastion.example.com]        # when the host is behind a bastion

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

Like every other permission, `release:create` and `release:read` are denied by default. Add them to `permissions`
in projects that use releases. The device flow token already has the `repo` scope, so re-authentication is not necessary.

```bash
git push origin v0.2.6                                   # the tag must exist upstream first
sekimore release create --tag v0.2.6                     # GitHub writes the notes from the merged PRs
sekimore release create --tag v0.2.6 --notes-file NOTES.md --draft
sekimore release view --tag v0.2.6
sekimore release list --limit 10
```

- The tag must already exist upstream, so run this command after pushing the tag. GitHub returns 422 when the tag does not exist.
- If no body is given, the relay sets `generate_release_notes`, and GitHub generates the notes from the pull requests merged
  since the previous tag. This is the usual workflow, and no notes need to be written by hand.
- With `--notes` or `--notes-file`, the given text is used as the body. If `--generate-notes` is also given, GitHub appends
  its generated notes after that text.
- `--title` defaults to the tag name, so a release always has a title. `--prerelease` marks the release as a prerelease.
- `--draft` creates the release unpublished and leaves publishing to a human. By default, the release is published.
- `sgw-agent release edit --tag v0.2.6 --draft false` publishes that draft and requires `release:publish`.
  Editing a release that remains a draft (`--title`, `--notes`, `--prerelease`) requires only `release:create`.

### Exfiltration controls: the 443 upload cap and `https-relay`

The relay never lets the AI use the operator's credentials. However, an HTTPS push that uses another person's credentials embedded in a prompt cannot be distinguished from normal traffic without inspecting the TLS content.
The 443 passthrough therefore limits the number of bytes that the dev container can send upstream (1 MiB by default; downloads are not counted).
Ordinary GET requests and API calls send far less than this limit, so the cap stops only large uploads such as a `git push`.

```yaml
domain_handlers:
  github.com: { handler: github, max_upload_bytes: 262144 }      # 256 KiB; HTTPS push is unnecessary because SSH goes through the relay
  ghcr.io:    { handler: https-relay, max_upload_bytes: -1 }     # unlimited for a registry you push your own images to
  registry-1.docker.io: { handler: https-relay }                 # uses the default (relay.https_max_upload_bytes)
relay:
  https_max_upload_bytes: 1048576
network:
  allowed_ports: [80, 443]      # destination ports allowed to permitted domains (a sekimore-gw setting; blocks traffic such as SSH to a bare IP address)
```

- DNS resolves an `https-relay` domain to the relay, and only port 443 goes through the relay's passthrough. Other ports cannot reach the domain.
- The relay closes a connection that exceeds the cap and records `https_upload_capped` in the audit log. The Relay tab marks connections that sent 1 MiB or more with LARGE UPLOAD and shows their count for the last 24 hours.
- Domains that remain in `allow_domains` bypass the relay entirely and have no cap. Move only the domains that need a cap to a handler.

Multiple upstreams: an SSH exec request does not carry a host name, so the relay listens on a separate port for each upstream and selects the upstream by the port that received the connection.
agent-setup writes a `Host` and `Port` entry for each upstream to `~/.ssh/config`, so the agent's URLs do not change.
On port 443, the relay selects the upstream by the TLS SNI. The relay's ssh does not read the host's `~/.ssh/config`, so configure bastions and proxies in `ssh_options`.
Add a bastion's host key with `sekimore-relay keyscan bastion.example.com --upstream ghe.example.com`.

`keyscan` and `login` both take host keys, with one difference on purpose:

- `keyscan <host>` prints the fingerprints and saves. The operator named the host on the command line; that is the confirmation.
- `login` asks yes/no first. It takes keys as a side effect of logging in, for hosts the operator did not name (the bastion, and the upstream through it), and a login must not quietly trust a host. A key step that ends without the key stops the login before the device flow, with a non-zero exit (0.2.45). To skip the question, run `keyscan` for each host first.

## Display language (0.2.4)

The CLI's messages are stored in `relay/locales/en.json` and `relay/locales/ja.json` and embedded in the binary.
The relay reads `SEKIMORE_LANG`, `LC_ALL`, `LC_MESSAGES` and `LANG`, in that order. A value matching `ja*` selects Japanese, and any other value selects English (the default).
A key that is missing from a dictionary falls back to English, and a key that is also missing from English falls back to the key name.

```bash
sekimore-relay check                     # English (default)
SEKIMORE_LANG=ja sekimore-relay check    # Japanese
sekimore guide --lang ja                 # prints only the guide in Japanese
```

Localization covers `--help`, operator-facing output, and `sgw-agent guide`.
The guide language is selected with `--lang en|ja`, and the guide's sources are `relay/share/agent-guide.en.md` and `relay/share/agent-guide.ja.md`.
Denial reasons (`sgw-agent: …`) and the audit log `audit.jsonl` intentionally remain in English, so that tools and agents can match on the strings.

## Operations (operator)

The Relay tab of the Web UI shows the configuration, permissions, tokens, access history and blocked attempts. The tab is read-only.
To open the Web UI in a dev container setup, run `mise run web`, which reads the published port from the running gateway container. With a standalone `docker compose` setup, open the port that your compose file publishes for the Web UI (the gateway listens on 8080 inside the container, and the sample `docker-compose.yml` publishes `8080:8080`).
Dev Containers setups also provide `mise run gw:tokens` / `gw:revoke-project` / `gw:audit` / `gw -- <args>`.

| Command | Purpose |
|---|---|
| `sekimore-relay check` | List the policy and current state |
| `sekimore-relay tokens` | List issued tokens (label / expiry / use count / state) |
| `sekimore-relay revoke --label skm_xxxxxxxx` | Revoke one token |
| `sekimore-relay revoke-project` | Revoke every token of the project (when the engagement ends) |
| `sekimore-relay bootstrap disable` / `enable` | Turn automatic registration off or on (kill switch) |
| `sekimore-relay add-key "ssh-ed25519 AAAA…"` | Register a public key manually |
| `sekimore-relay keyscan <host> [--port N] [--upstream <domain>]` | Add the host key of an upstream or a bastion to known_hosts (prints the fingerprint) |
| `sekimore-relay login` / `logout` / `whoami` `[--upstream <domain>]` | Manage upstream tokens |
| `tail -f /data/relay/audit.jsonl` | Follow the record of every action and every denial |

`/data/relay` is the gateway's volume (0700) and is not visible from the AI container.
A new bootstrap with the same key revokes the previous token, so each key has at most one valid token.
Token records are deleted automatically 7 days after they expire. `audit.jsonl` is the permanent record.

## Troubleshooting

| Symptom | Cause | Action |
|---|---|---|
| `SSH_AUTH_SOCK is not set in the gateway container` | The agent socket is not passed to the relay. | Check the mount and environment variable from step 2, and `ssh-add -l` on the Mac. |
| `ssh-agent socket … does not exist` / `cannot connect` | The forwarding was interrupted, or a permission error occurred. | Re-establish the forwarding. On EACCES, check the socket's owner. |
| `known_hosts … has no entry for <host>` | The upstream's host key is missing. | Run `sekimore-relay login` or `sekimore-relay keyscan <host>`. |
| `repository "X" is not in project "P"` | The repository is outside the project. | Add it to `repos`. If the denial is intended, no action is needed. |
| `push to refs/heads/main is not allowed` | The direct push targets a branch outside the allowed namespace. | Push to `refs/for/main` to open a PR. If necessary, add a glob to `push`. |
| `branch X already exists upstream` | The name is already in use and `on_exists` is `reject`. | Push under a different name, or update the branch with a direct push to `refs/heads/<branch>`. |
| `tag is not allowed for this repository` | Tag pushes are denied by default. | Add a glob to `tags` for that repository or upstream. |
| `Permission denied (publickey)` (from the relay) | The agent's key is not registered. | Run `sudo sekimore-agent-setup.sh`, or have the operator run `add-key`. Check whether `bootstrap.disabled` exists. |
| `! [remote rejected] … (sekimore: …)` | The policy denied the push. | Follow the instructions in the message. |
| `denied: token expired at …` | The project token has expired. | `sgw-agent` renews it automatically. In an older environment, run `sudo sekimore-agent-setup.sh`. |
| `no upstream token … run sekimore-relay login` | The device flow has not been run, or the operator has logged out. | Run `sekimore-relay login`. |
| `git ls-remote` hangs without output | DNS points to the relay, but the INPUT chain drops the packets. | Check whether `iptables-legacy -S INPUT` contains `--dport 22`. If it does not, the relay has not started. |
| `https://github.com/…` fails | `https` is set to `reject`, or the upstream is unreachable. | Restore the default `passthrough`. Check `https_failed` in the audit log. |
| `could not read Username` on HTTPS git | HTTPS authentication is blocked intentionally, so that the operator's credentials cannot bypass the relay. | Use SSH (`git@github.com:`). |
| The post-create message that the ssh-agent is being forwarded does not go away | `code` on macOS inherits the launchd environment. | Quit VS Code completely and run `mise run vscode`. |

### Troubleshooting the upstream proxy path from inside dev

All of this runs from the dev container. There is no need to go to the host.

```bash
# the running configuration, and the generated squid.conf
curl -s http://sekimore-gw:8080/api/config | jq '.proxy, .squid.config_text'
# the relay's refusal reasons
curl -s http://sekimore-gw:8080/api/relay/audit | jq '.[0:5]'
# Squid's path (dev gets HTTP_PROXY from the gateway; -x names Squid whatever the environment says)
curl -x http://sekimore-gw:3128 -sSI http://deb.debian.org/debian/dists/stable/Release | grep -i via
# the relay's own path: 443 goes to the relay, with no proxy named
curl -sS -o /dev/null -w '%{http_code}\n' https://api.github.com/
```

- Two `Via` hops (the upstream Squid and the gateway's Squid) prove the request went through the upstream.
- `407` with `Proxy-Authenticate` means the upstream was reached and only the authentication failed.
- `curl: (35) SSL_ERROR_SYSCALL` right after connecting to a relayed HTTPS domain, with `https_failed … proxy closed during CONNECT` in the audit, is the relay failing to reach the upstream proxy — Squid's path can still work at the same time. An `https://` upstream proxy (`upstream_proxy_tls: true`) needs gateway 0.2.39 or later (#192).

### Which traffic uses the upstream proxy

- The relay's own paths (git over SSH, the GitHub API, the 443 passthrough) always do, and so does a client that names Squid explicitly (`curl -x http://sekimore-gw:3128`).
- Dev's ordinary traffic to a destination that is only in `allow_domains` does not: its DNS answer admits the address into the firewall and the packet is NATed straight out, leaving no line in Squid's access.log (#212).
- `proxy.direct_egress: deny` stops admitting those addresses, so Squid is the only way out. DNS still answers, so names resolve; a client that ignores `HTTP_PROXY` then fails instead of leaving silently. `allow_ips` is unaffected. It needs an `upstream_proxy`, or the gateway refuses to start.
- The dev container gets `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` at start: `agent-setup.sh` reads `GET /api/proxy-env` and writes `/etc/profile.d/sekimore-proxy.sh` plus a marked block in `/etc/environment`. `NO_PROXY` carries every `domain_handlers` target — Squid refuses CONNECT to them on purpose — plus `proxy.no_proxy`. The dev image has to source `/etc/profile.d`, which sgw-devcontainer-base does from the version that ships this.
- `sekimore-relay check` prints the mode under `proxy:` as `egress:`, in yellow while direct egress is allowed.

With `upstream_proxy_tls: true` and Squid enabled, the relay does not speak TLS to the upstream proxy at all: it sends its CONNECT to the local Squid, which takes the TLS hop with OpenSSL and presents the stored credential itself (`cache_peer … login=`). That works with a proxy offering only TLS 1.2 RSA key exchange — a Squid `https_port` without `tls-dh=` — which the relay's rustls cannot speak (#205). With Squid disabled the relay speaks TLS itself: TLS 1.3 or ECDHE only. `sekimore-relay check` prints which route is in use, under `route:`, and its `reach:` line probes that route.

## Development

```bash
mise use rust@1.89                                  # or rustup
cargo test --features test-hooks                    # the e2e tests require git and ssh (CI sets SEKIMORE_E2E_REQUIRED=1)
cargo clippy --all-targets --features test-hooks -- -D warnings
cargo fmt --check
cargo audit                                         # every ignore in .cargo/audit.toml has a documented reason
cargo tree -i aws-lc-rs; cargo tree -i openssl-sys  # neither crate may be present
```

Running `mise run ci` at the root of sekimore-gw runs the Rust and Python lints and tests in parallel.
The `test-hooks` feature enables `LocalGitUpstream` (`git receive-pack` against a local bare repository). The image build does not include it.

## Building the image

The `relay-builder` stage of `sekimore-gw/Dockerfile` builds a static musl binary with `cargo-zigbuild` (CI uses a native runner for each architecture).
The binary does not depend on a specific glibc version, so it runs as is after a `COPY --from` into the dev container base image.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).
