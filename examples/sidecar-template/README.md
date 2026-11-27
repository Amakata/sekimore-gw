# Command sidecar template

A minimal command sidecar: in-memory notes with `note add` and `note list`. Python 3, standard
library only. Copy it and replace the commands.

The protocol: [docs/sidecar-protocol.md](../../docs/sidecar-protocol.md).

## Run it

```sh
python3 sidecar.py --socket /tmp/notes.sock
curl --unix-socket /tmp/notes.sock http://sidecar/describe
```

## config.yml

```yaml
relay:
  sidecars:
    notes:
      socket: /run/sekimore-sidecars/notes.sock
      resources: [notes]
      credentials:
        api_key: "{notes/api_key}"
  project:
    permissions: [notes:read, notes:write]   # with the project's other permissions
```

Set the credential on the host:

```sh
sgw var set notes/api_key --secret
```

## Compose

Add the service to `.devcontainer/docker-compose.relay.yml`, next to `sekimore-github`. Name it
`sekimore-<name>`, `<name>` being its key under `relay.sidecars`: that is how `sgw recreate`
finds it. It shares the `sekimore-sidecars` volume with the gateway, and never with dev. Copy
`sidecar.py` to `.devcontainer/sidecars/notes/` first.

```yaml
services:
  sekimore-notes:
    image: python:3.13-slim          # pin a digest for real use
    command: [python3, /app/sidecar.py, --socket=/run/sekimore-sidecars/notes.sock]
    networks:
      internal-net: {}
    volumes:
      - ./sidecars/notes/sidecar.py:/app/sidecar.py:ro
      - sekimore-sidecars:/run/sekimore-sidecars
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    read_only: true
    restart: unless-stopped
```

## Start it

On the host, once `config.yml`, the credential and the compose service are in place:

```sh
sgw recreate      # the gateway reads config.yml again, and sekimore-notes is (re)created
sgw refresh       # only if `sgw-agent notes --help` in dev does not list the commands yet
```

`sgw recreate` recreates `sekimore-<name>` for every name under `relay.sidecars` that the
compose declares, running or not, and nothing else of the stack (not dev). The template keeps
its notes in memory, so `sgw recreate` empties them. A configured sidecar with no such
service is named in one line. It then runs the agent's setup in dev, which reads the commands;
a sidecar still starting at that moment is listed as not available, and `sgw refresh` reads them
again. Rebuild Container is not needed.

Later:

| Change | On the host |
|---|---|
| `config.yml` (permissions, credentials, a new sidecar) | `sgw recreate`, then `sgw refresh` if needed |
| The sidecar's service in compose | `sgw recreate` |
| `sidecar.py` itself (its commands) | `sgw recreate`, then `sgw refresh` if needed |

Each `sgw recreate` restarts the sidecar: the template's notes are lost.

## Use it

```sh
sgw-agent notes note add --text "check the release notes" --tag release
sgw-agent notes note list --limit 5
```
