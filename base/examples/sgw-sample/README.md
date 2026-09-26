# sgw-sample

*[日本語版](README.ja.md)*

The project template `sgw init --devcontainer` writes: a dev container built on
`sgw-devcontainer-base` behind `sekimore-gw`. It includes:

- an isolated network in which all traffic goes through `sekimore-gw`
- the configuration of `sekimore-relay`, the relay that carries git and the GitHub API
  (`docker-compose.relay.yml`). The AI agent uses `git@github.com:Org/Repo.git` unchanged; its
  key is disposable, and the connection to the upstream is authenticated with the operator's
  ssh-agent inside the gateway. The relay refuses repositories outside the project and
  operations that are not permitted
- a minimal `Dockerfile` that only builds `FROM` the base image, with an example of installing
  specific language versions with `mise`

This directory is the readable copy; `sgw` carries the same files and writes them. Do not copy
it by hand: `sgw init` does, with the pins of its own version.

## Usage

The steps are in [base/README.md](../../README.md): `sgw init`, `.env`, `config.yml`,
`sgw open`, `sgw unlock`, `sgw login`, `sgw signing-key`, `sgw verify`. What is worth knowing
behind them:

- **VS Code must start without `SSH_AUTH_SOCK`** (`sgw open`). The Dev Containers extension
  always forwards the operator's ssh-agent into the dev container and no setting disables it.
  On macOS the `code` CLI starts the application through `open`, so `env -u SSH_AUTH_SOCK code`
  changes nothing; `sgw open` removes the variable from launchd, starts the application directly
  and checks its environment (`sgw open --check`). Before restarting Docker Desktop, run
  `sgw open --restore-agent-env`. Opened the usual way, post-create **stops with an ERROR** and
  says so.
- **The secret store is locked after every recreate** (`sgw unlock`; `sgw keychain-set` once
  makes `sgw recreate` unlock it). The upstream API token lives in it: locked, the relay cannot
  use the GitHub API (git push and pull use SSH and still work).
- The signing key's comment, which becomes its title on GitHub, is
  `sekimore-agent-signing: <project> / <your name> <email>`; `SEKIMORE_SIGNING_KEY_COMMENT` in
  `.env` changes it.
- After adding or changing an upstream in `config.yml`: `sgw restart`, then `sgw refresh` (it
  rebuilds dev's `~/.ssh/config` Host blocks and the proxy environment without Rebuild Container).
- Routine: `sgw check`, `sgw tokens`, `sgw audit`, `sgw revoke-project` (when the project ends),
  `sgw relay <any sekimore-relay subcommand>`.

To use the template without the relay, remove `docker-compose.relay.yml` from `dockerComposeFile`
in `devcontainer.json`, and delete `domain_handlers:` and `relay:` from `config/config.yml`.

The mise tasks in `.devcontainer/sgw/` (`mise run gw:unlock`, `mise run relay:verify`, …) do
the same as the `sgw` commands, for a project that uses them; `mise tasks` lists them.

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
    ├── .env.sample                 # sgw init copies it to .env
    ├── .gitignore
    ├── config/
    │   ├── config.yml              # sekimore-gw's allowlist of domains, and the relay's project policy
    │   └── squid/
    │       └── squid.conf.template
    ├── scripts/
    │   └── post-create.sh          # unpacks zsh rc.d, detects agent forwarding (and stops with an ERROR)
    ├── sgw/                        # distributed: sgw update --apply replaces all of it. Do not edit
    │   ├── tasks.mise.toml         # the host-side mise tasks (vscode / web / relay:verify / upgrade ...)
    │   ├── gateway.mise.toml       # the gateway's mise tasks (gw:*)
    │   ├── sgw.sh                  # finds the gateway / dev container by compose label and runs docker exec in it
    │   ├── vscode.sh               # what sgw open runs
    │   ├── upgrade.sh              # mise run upgrade
    │   ├── post-start.sh           # run by postStartCommand: agent-setup (with every SEKIMORE_* variable), docker-init, post-create
    │   └── MANIFEST                # what sgw update / upgrade wrote last, used to detect manual edits
    └── zsh-config/
        └── rc.d/                   # the project's own zsh configuration
```
