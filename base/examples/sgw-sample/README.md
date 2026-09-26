# sgw-sample

*[日本語版](README.ja.md)*

A minimal dev container built on `sgw-devcontainer-base`. It includes:

- An isolated network in which all traffic goes through `sekimore-gw`
- A configuration for `sekimore-relay`, the relay that carries git and GitHub API traffic
  (`docker-compose.relay.yml`). The AI agent uses `git@github.com:Org/Repo.git` unchanged, but
  its key is disposable, and the connection to the upstream is authenticated with the operator's
  ssh-agent inside the gateway. The relay refuses repositories outside the project and operations
  that are not permitted
- A minimal `Dockerfile` that only builds `FROM` the base image
- An example that installs specific versions of Python, Node.js, Ruby and Rust with `mise` (PHP
  is commented out in the Dockerfile and can be enabled when needed)

## Usage

The host-side operations (on a Mac with Docker Desktop) are mise tasks; `mise tasks` lists them.
The tasks are defined in `.devcontainer/sgw/`, which `mise run upgrade:apply` keeps up to date.
`mise.toml` belongs to your project and only includes those task files.

1. Copy `.devcontainer/.env.sample` to `.devcontainer/.env` and fill in the values.
   `SEKIMORE_AGENT_SOCK` is the operator's ssh-agent socket; on Docker Desktop, the default value
   is correct.
2. In `config/config.yml`, replace `relay.project.repos` and `permissions` with the values for
   this project.
3. Start Docker Desktop with the ssh-agent available, **quit VS Code completely (Cmd+Q)**, run
   **`mise run vscode`** in Terminal.app, and select "Reopen in Container".
   On macOS, the `code` CLI starts the application through `open`, so
   `env -u SSH_AUTH_SOCK code` does not affect the application's environment. The task removes
   `SSH_AUTH_SOCK` from launchd, starts the application directly, and then checks the
   application's environment (`mise run vscode:check`). Before you restart Docker Desktop, run
   `mise run vscode:restore-agent-env`.
   VS Code must start without `SSH_AUTH_SOCK` because the Dev Containers extension always
   forwards the operator's ssh-agent into the dev container, and no setting disables this. If VS
   Code is opened in the usual way, post-create **stops with an ERROR** and refers to this
   procedure.
4. Unlock the secret store with **`mise run gw:unlock`**. **This is required every time the
   gateway is recreated.** Since 0.2.19, the upstream API token is kept in this store,
   and while the store is locked, the relay cannot use the GitHub API at all (git push and pull
   use SSH, so they still work). The key is held only in memory, so unlock the store again
   whenever the gateway restarts.
5. The first time only, run **`mise run gw:login`** for the gateway (device flow; it saves the
   upstream token and `known_hosts`). It cannot run before the unlock, because the store it saves
   to is not yet open.
6. Register the signing public key that **`mise run dev:signing-key`** prints on GitHub, under
   Settings → SSH and GPG keys, as a "Signing Key". The AI agent's commits are signed with this
   key instead of yours. The key's comment, which becomes its Title on GitHub, is
   "sekimore-agent-signing: \<project\> / \<your name\> \<email\>". To change it, set
   `SEKIMORE_SIGNING_KEY_COMMENT` in `.env`.
7. Check the whole setup with **`mise run relay:verify`**. It checks the gateway's state, that
   no ssh-agent reaches the dev container, git through the relay, and the refusal of a repository
   outside the project.

Routine tasks: `mise run gw:check` (state), `mise run gw:tokens`, `mise run gw:audit` (the audit
log), `mise run relay:refresh` (after adding or changing an upstream in `config.yml`, and
`mise run gw:restart`: it rebuilds dev's `~/.ssh/config` Host blocks and the proxy environment
without Rebuild Container), `mise run gw:revoke-project` (when the project ends) and
`mise run gw -- <any sekimore-relay subcommand>`.

To use the sample without the relay, remove `docker-compose.relay.yml` from `dockerComposeFile`
in `devcontainer.json`, and delete `domain_handlers:` and `relay:` from `config/config.yml`. The
gw:* and relay:* tasks are then not needed either.

To use the sample for a new project, copy `.devcontainer/` and `mise.toml`. After that,
`mise run upgrade` reports whether newer versions exist, and `mise run upgrade:apply` updates to
them.

## Files

```
sgw-sample/
├── README.md
├── mise.toml                       # yours: includes .devcontainer/sgw/, and your own tasks
└── .devcontainer/
    ├── devcontainer.json
    ├── docker-compose.yml          # two services, dev and sekimore-gw
    ├── docker-compose.relay.yml    # the overlay for sekimore-relay (the agent socket mount, the key volume)
    ├── Dockerfile                  # FROM sgw-devcontainer-base, plus specific versions installed with mise
    ├── .env.sample
    ├── .gitignore
    ├── config/
    │   ├── config.yml              # sekimore-gw's allowlist of domains, and the relay's project policy
    │   └── squid/
    │       └── squid.conf.template
    ├── scripts/
    │   └── post-create.sh          # unpacks zsh rc.d, detects agent forwarding (and stops with an ERROR)
    ├── sgw/                        # distributed: mise run upgrade:apply replaces all of it. Do not edit
    │   ├── tasks.mise.toml         # the host-side tasks (vscode / web / relay:verify / upgrade ...)
    │   ├── gateway.mise.toml       # the gateway's tasks (gw:*), for the gateway version in use
    │   ├── sgw.sh                  # finds the gateway / dev container by compose label and runs docker exec in it
    │   ├── vscode.sh               # mise run vscode
    │   ├── upgrade.sh              # mise run upgrade
    │   ├── post-start.sh           # run by postStartCommand: agent-setup (with every SEKIMORE_* variable), docker-init, post-create
    │   └── MANIFEST                # what upgrade wrote last, used to detect manual edits
    └── zsh-config/
        └── rc.d/                   # the project's own zsh configuration
```
