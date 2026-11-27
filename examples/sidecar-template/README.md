# Command sidecar template

A minimal command sidecar: in-memory notes with `note add` and `note list`. Go, standard library
only, in one file (`main.go`). Copy the directory and replace the commands.

The protocol: [docs/sidecar-protocol.md](../../docs/sidecar-protocol.md). It is HTTP over a Unix
socket with JSON bodies, so a sidecar can be written in any language; this one is in Go.

| File | What it is |
|---|---|
| `main.go` | The sidecar |
| `main_test.go` | Its tests, on a real socket, with a copy of the gateway's checks of `/describe` |
| `go.mod` | The module: no requirements, so no `go.sum` |
| `Dockerfile` | The image the compose service builds |

## Run it

```sh
go run . --socket /tmp/notes.sock
curl --unix-socket /tmp/notes.sock http://sidecar/describe
```

Test it after a change:

```sh
gofmt -l . && go vet ./... && go test ./...
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

Copy this directory to `.devcontainer/sidecars/notes/`. Then add the service
to `.devcontainer/docker-compose.relay.yml`, next to `sekimore-github`. Name it `sekimore-<name>`,
`<name>` being its key under `relay.sidecars`: that is how `sgw recreate` finds it. It shares the
`sekimore-sidecars` volume with the gateway, and never with dev.

```yaml
services:
  sekimore-notes:
    build: ./sidecars/notes
    pull_policy: build               # rebuilt on each `sgw recreate`, so a change to main.go is picked up
    command: [--socket=/run/sekimore-sidecars/notes.sock]
    networks:
      internal-net: {}
    volumes:
      - sekimore-sidecars:/run/sekimore-sidecars
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    read_only: true
    restart: unless-stopped
```

The image is built in two stages: the `golang` image compiles a static binary, and the image
that runs holds that binary and the CA certificates only (`FROM scratch`). The build fetches no
module; it pulls the `golang` image and nothing else. Its `FROM` line is pinned by digest: pin
your own when you copy it (`docker buildx imagetools inspect golang:<version>` prints it).

`pull_policy: build` matters. `sgw recreate` runs `docker compose up -d --force-recreate --no-deps`
on the sidecar, and without it Compose builds the image only when there is none, then keeps
running the first build. With it, every recreate rebuilds (from the cache when nothing changed).

## Start it

On the host, once `config.yml`, the credential and the compose service are in place:

```sh
sgw recreate      # the gateway reads config.yml again, and sekimore-notes is built and (re)created
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
| `main.go` itself (its commands) | `sgw recreate` (it rebuilds the image: `pull_policy: build`), then `sgw refresh` if needed |

Each `sgw recreate` restarts the sidecar: the template's notes are lost.

## Use it

```sh
sgw-agent notes note add --text "check the release notes" --tag release
sgw-agent notes note list --limit 5
```
