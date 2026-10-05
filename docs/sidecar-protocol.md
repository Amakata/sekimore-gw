# The command sidecar protocol

For people writing a **command sidecar**: a small service that gives the agent commands of its own
(`sgw-agent notes note add …`), checked and audited by the gateway. sekimore-gw 0.3.0 and later.

A working example is [examples/sidecar-template](../examples/sidecar-template/) (Python, standard
library only).

## Two kinds of sidecar

| | Forge relay | Command sidecar |
|---|---|---|
| Name under `relay.sidecars` | a known forge: `github` | any other name: `notes`, `s3`, … |
| Serves | the gateway's own operations (`pr create`, …) | commands it declares itself |
| Resources | the gateway's (`pr`, `issue`, …) | its own (`notes`), never the gateway's |
| Endpoints | `GET /describe`, `POST /call`, `/query`, `/open-pr` | `GET /describe`, `POST /command` |
| Written by | this project | anyone |

This document is about command sidecars.

## How a call travels

```
agent ── POST /x/notes/note/add ──▶ gateway ── POST /command ──▶ sidecar
         {"args": {...}}            1. finds the command        (Unix socket)
                                    2. checks the permission
                                    3. checks the arguments
                                    4. adds the credentials
                                    5. audits the reply's calls
```

The sidecar decides nothing. What reaches it is already allowed.

## Transport

- HTTP/1.1 over a Unix socket. JSON bodies (`Content-Type: application/json`).
- One request per connection is enough. The gateway opens a new connection for each exchange.
- The socket lives on a volume that the gateway and the sidecar share, and the dev container does
  not mount (`sekimore-sidecars:/run/sekimore-sidecars` in the template's compose file).
- The sidecar creates the socket: remove a stale one, bind, `chmod 0660`.
- Answer every request you understand with **HTTP 200**. A non-2xx status means "the sidecar is
  broken": the agent gets 503 and the audit gets `sidecar_unavailable`. Report a failed command
  in the `error` field instead (below).

## `GET /describe`

Who the sidecar is and what it offers.

```json
{
  "name": "notes",
  "version": "0.1.0",
  "resources": ["notes"],
  "guide": "## notes\n\n- `sgw-agent notes note add --text <text>` adds a note [notes:write]\n",
  "commands": [
    {
      "name": "note add",
      "about": "Add a note",
      "permission": "notes:write",
      "args": [
        {"name": "text", "help": "The note", "kind": "string", "required": true},
        {"name": "tag", "help": "A tag; repeat for more", "kind": "list"},
        {"name": "pin", "help": "Pin the note", "kind": "bool"}
      ]
    },
    {"name": "note list", "about": "List the notes", "permission": "notes:read"}
  ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | Must equal the key under `relay.sidecars` |
| `version` | yes | Free text, logged |
| `resources` | yes | The resources its permissions use |
| `guide` | yes | How to use it, for the agent ([below](#writing-the-guide)) |
| `commands` | no | The commands |
| `commands[].name` | yes | 1–3 words, space-separated: `note add` |
| `commands[].about` | yes | One line for `--help` |
| `commands[].permission` | yes | `<resource>:<action>`, the resource one of its own |
| `commands[].args` | no | The arguments |
| `args[].name` | yes | `--<name>` on the command line, `"<name>"` on the wire |
| `args[].help` | no | One line |
| `args[].kind` | no | `string` (default), `int`, `bool`, `list` |
| `args[].required` | no | Default `false` |

A missing required field makes the whole describe unreadable, and the sidecar is not connected.

### Argument kinds

| `kind` | On the wire | On the command line |
|---|---|---|
| `string` | a JSON string | `--text hi` |
| `int` | a JSON integer (`3`, not `3.0`) | `--limit 3` |
| `bool` | `true` / `false` | `--pin` (a flag) |
| `list` | a JSON array of strings | `--tag a --tag b` |

### What the gateway checks

A **word** is lower-case letters, digits, `_` and `-`, starting with a letter.

| Rule | Example refused |
|---|---|
| `name` equals the key under `relay.sidecars` | `"name": "memo"` under `relay.sidecars.notes` |
| every resource is listed in `relay.sidecars.<name>.resources` | `"resources": ["notes", "s3"]` |
| `guide` is not empty | `"guide": " "` |
| every `[resource:action]` in the guide uses one of its resources | `merge with [pr:merge]` |
| a command name is 1–3 words | `Note Add`, `a b c d` |
| no command name is the start of another (a group cannot be a command) | `note` and `note add` |
| a permission is `<one of its resources>:<word>` | `pr:merge`, `notes` |
| an argument name is a word, and not `help` | `Text`, `help` |
| no argument is declared twice | two `text` |
| a `bool` argument is not `required` | `{"kind": "bool", "required": true}` |

The configuration adds: its resources are never the gateway's (`ci`, `issue`, `pr`, `project`,
`release`, `repo`, `search`, `security`), and no two sidecars claim the same resource.

A refused describe is audited as `sidecar_refused`, and every call answers 503 with the reason.

### When it is read

- On the first call, then kept.
- A failed read is not kept: the sidecar may still be starting, and the next call looks again.
- When a call names a command the kept describe does not have, it is read once more. A sidecar
  updated in place gets its new commands without restarting the gateway.

## `POST /command`

The request. Everything in it has been checked.

```json
{
  "command": "note add",
  "permission": "notes:write",
  "project": "my-project",
  "args": {"text": "hi", "tag": ["a", "b"]},
  "credentials": {"api_key": "…"}
}
```

| Field | Meaning |
|---|---|
| `command` | The command's name as declared |
| `permission` | The permission the gateway checked, for your log |
| `project` | `relay.project.name` |
| `args` | Only declared names, every required one, each of its kind. An omitted or `null` argument is absent |
| `credentials` | `relay.sidecars.<name>.credentials`, values from the secret store. `{}` when none are configured |

The reply. Every field is optional; `calls` defaults to `[]`.

```json
{
  "message": "added note 1",
  "data": {"id": 1, "text": "hi"},
  "calls": [{"method": "POST", "path": "/v1/notes", "status": 201}]
}
```

```json
{
  "error": {"status": 404, "message": "no note 7"},
  "calls": [{"method": "GET", "path": "/v1/notes/7", "status": 404}]
}
```

| Field | Meaning |
|---|---|
| `message` | For the agent to read: what happened, in a sentence or a few lines |
| `data` | For the agent to parse (shown with `--json`) |
| `error.status` | The HTTP status the agent gets (an invalid one becomes 502) |
| `error.message` | What went wrong and what to do; the agent reads it |
| `calls` | Every upstream call made for this command. The gateway writes each to its audit as `api_call` |

Report calls even when the command failed. Leaving one out hides nothing: the connection still
crossed the gateway's 443 passthrough, which logs it.

### Status codes the agent sees

| Status | When |
|---|---|
| 200 | The reply had no `error` |
| `error.status` | The reply had an `error` |
| 400 | An argument is unknown, missing or of the wrong kind (the sidecar is not called) |
| 403 | The project does not grant the command's permission (the sidecar is not called) |
| 404 | No such sidecar, or no such command after re-reading the describe |
| 502 | The reply is not readable JSON |
| 503 | The sidecar does not answer, answered non-2xx, did not reply in time, its describe was refused, or a credential is missing or the secret store is locked |

### Limits

| What | Limit |
|---|---|
| The agent's request to the gateway | `relay.limits.api_body_max_bytes` (1 MiB by default) |
| A reply the gateway reads | 32 MiB |
| One exchange, connect to last byte | 120 s |
| What the sidecar reads | Its own choice. Cap it; the template takes 8 MiB |

## Configuration

`config.yml`:

```yaml
relay:
  sidecars:
    notes:
      socket: /run/sekimore-sidecars/notes.sock   # absolute, on the shared volume
      resources: [notes]                          # what its describe may claim
      credentials:                                # optional; sent with each call
        api_key: "{notes/api_key}"                # a reference, never the value
  project:
    permissions: [pr:create, notes:read, notes:write]
```

- `resources` is what the operator allows. A describe that claims more is not connected.
- `credentials` values are references written `"{key}"`. Each person sets the value on the host:

  ```sh
  sgw var set notes/api_key --secret     # --secret: write-only, never shown back
  ```

  A value written in `config.yml` is refused: the file is in the worktree, readable from dev.
- `upstreams` is for forge relays only.
- A sidecar's permissions (`notes:read`) go in `relay.project.permissions` **only**. Repository,
  upstream and board layers refuse them: the resource is not about a repository.

The compose service runs next to the gateway, on the internal network, with the socket volume.
See [the template's README](../examples/sidecar-template/README.md#compose).

## What the agent sees

The command line is the describe:

```sh
sgw-agent notes note add --text hi --tag a --tag b --pin
sgw-agent notes note list --limit 5 --json
```

(The `sgw-agent` side of this lands with #330; the gateway's API below is in place.)

Underneath, it is `POST /x/<sidecar>/<word>/<word>` with the project token:

```json
{"args": {"text": "hi", "tag": ["a", "b"], "pin": true}}
```

The answer is `{"ok": true, "message": …, "raw": <data>}`, or `{"ok": false, "error": …}` with
the status above. `sgw-agent whoami` lists the granted ones on a line of their own:
`sidecar permissions (sgw-agent <sidecar> …): notes:read notes:write`.

## What the gateway guarantees

A sidecar may take these as given:

- A `POST /command` that arrives is allowed. The project grants its permission.
- `args` match the declaration: no unknown name, every required one, each of its kind.
- `credentials` hold exactly what `relay.sidecars.<name>.credentials` names, from the secret store.
  No other sidecar's keys are sent.
- The audit is written by the gateway: the agent's call, and every call in `calls`. Credential
  values are never in it.

## What the gateway does not trust

- The name and resources in the describe: held to `relay.sidecars.<name>`.
- Each command's permission: it must use the sidecar's own resources.
- The guide: it may not tell the agent about permissions that are not the sidecar's.
- The reply: its size and time are capped, and its `error.status` is checked.

Naming and granting are separate. The sidecar names what it does; only `config.yml` grants it.

## What a sidecar must not do

| Don't | Why |
|---|---|
| Store a credential (disk, memory between calls, its own config) | It arrives with every call. A copy kept is a copy to steal and to revoke separately |
| Log a credential, or put it in `message`, `data` or `error` | Logs and replies are read by people and by the agent |
| Decide permissions, or second-guess the project's grants | The gateway has decided. Two deciders disagree, and only one is audited |
| Write its own audit | The gateway's audit is the record. Report upstream calls in `calls` |
| Reach the network directly | Every exit goes through the gateway ([below](#reaching-a-service)) |
| Answer a failed command with a non-2xx status | That reads as "the sidecar is down"; use `error` |
| Keep state it cannot lose | Restarting a sidecar must be safe. Keep what matters in the service it fronts |

## Reaching a service

Run the sidecar on the internal network only. It reaches its service through the gateway's 443
passthrough, so its traffic passes the same SNI check, upload cap and audit as dev's.

1. List the service's host under `domain_handlers` with `handler: https-relay`:

   ```yaml
   domain_handlers:
     api.notes.example:
       handler: https-relay
   ```

2. Dial the gateway at port 443 and keep the service's name for SNI and certificate checks. In
   Python:

   ```python
   import socket, ssl
   raw = socket.create_connection(("sekimore-gw", 443))
   tls = ssl.create_default_context().wrap_socket(raw, server_hostname="api.notes.example")
   ```

   A name not under `domain_handlers` goes to the default upstream, not to your service.

## Writing the guide

The guide is how the agent learns the sidecar's commands. Write it for an AI reader.

- English, Markdown, short. Start with a `## <name>` heading.
- One line per command: the exact command line, what it does, its permission in brackets.
- Name permissions as `[resource:action]`, and only your own. Naming another (`[pr:merge]`) refuses
  the describe.
- Say what the agent cannot work out alone: limits, side effects, what a failure means and what to
  do next.

```markdown
## notes

Short notes kept by the notes sidecar for this project.

- `sgw-agent notes note add --text <text> [--tag <tag>]... [--pin]` adds a note [notes:write]
- `sgw-agent notes note list [--limit <n>]` lists the notes, newest first [notes:read]
```

Write `error.message` the same way: what went wrong and the command that fixes it.

## Checking a sidecar

```sh
curl --unix-socket /run/sekimore-sidecars/notes.sock http://sidecar/describe
curl --unix-socket /run/sekimore-sidecars/notes.sock http://sidecar/command \
  -H 'Content-Type: application/json' \
  -d '{"command": "note list", "permission": "notes:read", "project": "p", "args": {}, "credentials": {"api_key": "x"}}'
```

The template's tests run it this way and through the gateway:
`tests/unit/test_sidecar_template.py`, `relay/tests/command_sidecar.rs`.
