# sgw-sample

*[日本語版](README.ja.md)*

The files `sgw init --devcontainer` writes: a dev container built on `sgw-devcontainer-base`,
behind `sekimore-gw`. This directory is the readable copy; `sgw` carries the same files. Do not
copy it by hand.

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
    │   ├── post-start.sh           # the way before base 0.2.51; postStartCommand is sgw-post-start now
    │   └── MANIFEST                # what sgw update / upgrade wrote last, used to detect manual edits
    └── zsh-config/
        └── rc.d/                   # the project's own zsh configuration
```

## Worth knowing

- VS Code must start without `SSH_AUTH_SOCK`, which is what `sgw open` does. Opened the usual way, post-create stops with an ERROR
- The secret store is locked after every recreate. Locked, the relay cannot use the GitHub API; git over SSH still works
- After adding or changing an upstream in `config.yml`: `sgw restart`, then `sgw refresh`
- The signing key's title on GitHub is `sekimore-agent-signing: <project> / <name> <email>`; `SEKIMORE_SIGNING_KEY_COMMENT` in `.env` changes it
- When the project ends: `sgw revoke-project`
- The mise tasks in `.devcontainer/sgw/` do the same as the `sgw` commands (`mise tasks` lists them)

## Keeping up to date

`.devcontainer/sgw/` is distributed: `sgw update --apply` replaces it, so do not edit it. To change
a task, define one with the same name in `mise.toml`.

```bash
sgw update            # what is newer, which files change, what UPGRADING asks. Changes nothing
sgw update --apply    # move to it
```

`sgw update --apply`:

1. raises the gateway's `image:` tag and the `FROM` tag to `sgw`'s own version
2. replaces `.devcontainer/sgw/`
3. recreates the gateway, after asking
4. unlocks the store when the passphrase is stored
5. lists what only the operator can do: Rebuild Container, the [UPGRADING.md](../../../UPGRADING.md) sections crossed (`sgw update --notes`), a commit

It stops when a file in `.devcontainer/sgw/` was edited by hand (`--force` overwrites).
