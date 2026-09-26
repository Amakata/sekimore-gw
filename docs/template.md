# The project template

*[日本語版](template.ja.md)*

The files `sgw init --devcontainer` writes: a dev container built on `sgw-devcontainer-base`,
behind `sekimore-gw`. They live in
[relay/templates/devcontainer/](../relay/templates/devcontainer/), the readable copy; `sgw`
carries the same files, byte for byte. Do not copy them by hand.

## Files

```
<your project>/
├── sgw.toml                        # sgw's record: the sha of each file as it wrote it (do not edit)
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
    └── zsh-config/
        └── rc.d/                   # the project's own zsh configuration
```

## Worth knowing

- VS Code must start without `SSH_AUTH_SOCK`, which is what `sgw open` does. Opened the usual way, post-create stops with an ERROR
- The secret store is locked after every recreate. Locked, the relay cannot use the GitHub API; git over SSH still works
- After adding or changing an upstream in `config.yml`: `sgw restart`, then `sgw refresh`
- The signing key's title on GitHub is `sekimore-agent-signing: <project> / <name> <email>`; `SEKIMORE_SIGNING_KEY_COMMENT` in `.env` changes it
- When the project ends: `sgw revoke-project`

## Keeping up to date

Everything `sgw init` wrote is yours to edit. `sgw.toml` is sgw's record of what it wrote (the
sha of each file), so `sgw update` can tell a file you edited from one a new version changes.

```bash
sgw update            # what is newer, which files change, what UPGRADING asks. Changes nothing
sgw update --apply    # move to it
```

`sgw update --apply`:

1. raises the gateway's `image:` tag and the `FROM` tag to `sgw`'s own version
2. overwrites a template file that is still as sgw wrote it when this version changes it; leaves
   one you edited alone; when both happened, writes this version's file beside yours as
   `<file>.sgw-new` for you to merge (`--force` overwrites)
3. recreates the gateway, after asking
4. unlocks the store when the passphrase is stored
5. lists what only the operator can do: Rebuild Container, the [UPGRADING.md](../UPGRADING.md) sections crossed (`sgw update --notes`), a commit

A project from before 0.2.52 still has `.devcontainer/sgw/` (the mise layer) and a `mise.toml`
that includes it; `sgw update --apply` removes the directory and those lines, and keeps your
own tasks.
