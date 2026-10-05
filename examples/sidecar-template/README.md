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

Add the service to `.devcontainer/docker-compose.relay.yml`, next to `sekimore-github`. It shares
the `sekimore-sidecars` volume with the gateway, and never with dev. Copy `sidecar.py` to
`.devcontainer/sidecars/notes/` first.

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

Then Rebuild Container: a new service is started only by compose. Later changes to `config.yml`
or to the sidecar's commands need, on the host:

```sh
sgw recreate      # the gateway reads config.yml again
sgw refresh       # the agent's CLI picks up the commands
```

## Use it

```sh
sgw-agent notes note add --text "check the release notes" --tag release
sgw-agent notes note list --limit 5
```
