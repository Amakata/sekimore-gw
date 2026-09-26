<!-- reviewed-up-to: 0.2.51 -->
# Upgrading: the changes each release requires

*[日本語版](UPGRADING.ja.md)*

**This guide lists only the releases that require you to change a file you own.**
For any release that is not listed, running `mise run upgrade:apply` is the whole upgrade
(before base 0.2.20, raise the image tag and run `mise run gw:recreate` instead). For what
changed in each release, see the [changelog](CHANGELOG.md).

"A file you own" is a file that you copied from the sample:

| File | Owner |
|---|---|
| `.devcontainer/config/config.yml` | You. It contains the relay's configuration. |
| `mise.toml` | You. It includes the host-side tasks and contains your own tasks. |
| `.devcontainer/docker-compose.yml` | You. It contains the gateway's image tag (`upgrade:apply` rewrites the tag and nothing else). |
| `.devcontainer/sgw/` | **Not you** from base 0.2.20: `upgrade:apply` replaces it. Before base 0.2.20, you owned `.devcontainer/scripts/sgw.sh`. |

## Where to start reading

| Your current gateway | Read from |
|---|---|
| 0.0.x | [0.1.0](#010-the-relay-arrived) onward. If you do not want the relay, **you do not need to do anything**. |
| 0.1.0 – 0.1.8 | [0.1.9](#019-permissions-moved) onward |
| 0.1.9 – 0.2.6 | [0.2.7](#027-declare-your-projects-boards-breaking) onward |
| 0.2.7 – 0.2.14 | [0.2.15](#0215-a-secret-store-appeared) onward |
| 0.2.15 – 0.2.18 | [0.2.19](#0219-unlocking-became-required) |
| 0.2.19 – 0.2.21 | [0.2.22](#0222-the-proxy-credential-moved-into-the-store), **only if your upstream proxy requires a password** |
| 0.2.22 – 0.2.26 | [0.2.27](#0227-tags-have-to-be-signed), **only if the agent pushes tags** |
| 0.2.27 | [0.2.28](#0228-dependabot-alerts-are-optional), **only if you want the agent to read Dependabot alerts** |
| 0.2.28 | [0.2.29](#0229-unattended-unlock-is-available), **only if you want unattended unlock or want AI commits to remain Verified** |
| 0.2.29 – 0.2.36 | [0.2.37](#0237-the-gateway-needs-pid-host), **everyone** |
| 0.2.37 – 0.2.43 | [0.2.44](#0244-a-proxyjump-bastions-host-key-has-to-be-known), **only if an upstream uses a `ProxyJump` bastion** |
| 0.2.44 | [0.2.45](#0245-gwlogin-asks-on-a-terminal-and-stops-without-a-host-key), **only if an upstream needs a host key the gateway has not saved** |
| 0.2.45 – 0.2.50 | [0.2.51](#0251-poststartcommand-is-one-line-sgw-post-start), **everyone, one line in devcontainer.json** |
| 0.2.51 | [0.2.52](#0252-the-mise-layer-is-gone-sgw-update---apply-removes-it), **everyone: `sgw update --apply`, then commit** |

Independently of the gateway version, a project created before base 0.2.20 must move to
`.devcontainer/sgw/` once, by hand. See
[base 0.2.20](#base-0220-devcontainersgw-and-mise-run-upgrade). After that move,
`mise run upgrade` lists each section of this guide that an upgrade crosses.

---

## 0.1.0 the relay arrived

**The relay is opt-in.** If `config.yml` has no `domain_handlers` and no `relay`, the relay
does not start, and the gateway behaves as in 0.0.x: DNS filtering, the firewall and Squid
are unchanged. No configuration key was removed or renamed. `allow_domains`,
`block_domains`, `allow_ips`, `block_ips`, `proxy`, `network` and `database_path` are all
still parsed. To move to a newer version without the relay, raise the image tag and run
`mise run gw:recreate`.

To adopt the relay, see [Adopting the relay from 0.0.x](#adopting-the-relay-from-00x).

### Adopting the relay from 0.0.x

The relay requires components that a 0.0.x setup does not have. The relay's part of the setup
is in a separate overlay compose file, so three additions are needed:

1. `domain_handlers` and `relay` in `config.yml`
   (the end of [`config/config.sample.yml`](https://github.com/Amakata/sekimore-gw/blob/main/config/config.sample.yml)
   is the current template)
2. A copy of [`docker-compose.relay.yml`](examples/sgw-sample/.devcontainer/docker-compose.relay.yml),
   listed in `dockerComposeFile` in `devcontainer.json` **after** `docker-compose.yml`.
   This file contains the ssh-agent mount and the disposable-key volume
3. `.env.sample` copied to `.env`, with the project name and the other values filled in (the
   overlay reads it)

Then run `mise run gw:unlock`, `gw:login`, `dev:signing-key` and `relay:verify`, in that order.

To stop using the relay, remove the overlay from `dockerComposeFile` and delete `domain_handlers`
and `relay` from `config.yml`. The gateway then behaves as 0.0.x did.

With all of these additions, the `.devcontainer/` differs substantially from a 0.0.x setup, so
**it is faster to copy the template again and carry over `allow_domains` and the other
settings.**

The breaking changes in the later sections of this guide (0.1.9, 0.2.7 and others) affect only
setups that have used the relay since 0.1.x. A move from 0.0.x configures the relay from
scratch with the current template, so none of them applies.

## 0.1.9 permissions moved

`relay.allow_tags` and `relay.allow_delete` are deprecated. **The relay still reads them**:
at start-up, it logs a warning and folds them into the `relay.project` defaults. Nothing
breaks if you leave them in place. To migrate, write the following:

```yaml
relay:
  project:
    tags: ["*"]        # was relay.allow_tags: true
    delete: true       # was relay.allow_delete: true
```

## 0.2.7 declare your Projects boards (breaking)

**If you use Projects v2, you must act.** If you do not list the boards that this project
may access, the relay refuses **every** Projects operation. A board's node ID is opaque and
does not identify the board's owner. Without a list, the agent could therefore reach any
board that the upstream token can see.

```yaml
relay:
  project:
    boards:
      - { org: acme, number: 3 }       # github.com/orgs/acme/projects/3
      - { user: someone, number: 1 }   # github.com/users/someone/projects/1
```

If you do not use Projects, no action is required.

The same release renamed `handler: git-relay` to `handler: github`. The old name
**still works as an alias**, so you do not need to edit it.

## 0.2.13 a window for config reloads

The default is `auto`, which keeps the previous behavior. However, the dev container can
write to `config.yml`, so **close the reload window before you hand work to an agent**:

```yaml
reload: manual        # or a duration, e.g. 30m
```

```bash
mise run gw:reload-freeze    # close the window now
mise run gw:reload-status    # show whether the window is open or closed
```

These commands require the three `gw:reload-*` tasks in `mise.toml`. The sample contains
them.

## 0.2.15 a secret store appeared

`mise.toml` needs the unlock tasks, and `sgw.sh` needs the **`gw-tty`** branch. `gw-tty`
connects the passphrase prompt to a terminal. The plain `gw` branch passes `-t` only when
stdout is also a terminal. A task runner turns stdout into a pipe, so without `gw-tty` the
prompt has no terminal.

Copy both from the sample:

```bash
diff -u <base>/examples/sgw-sample/mise.toml mise.toml
diff -u <base>/examples/sgw-sample/.devcontainer/scripts/sgw.sh .devcontainer/scripts/sgw.sh
```

The required tasks are `gw:unlock`, `gw:lock`, `gw:store-status` and `gw:passphrase`.

## 0.2.18 the store can be backed up

Add `gw:store-export` and `gw:store-import` to `mise.toml`. An export does not require the
key, so you can export a locked store. The export remains sealed, but **the passphrase is
the only protection for it**.

## 0.2.19 unlocking became required

**The upstream API token is now stored in the secret store, so the relay cannot reach the
GitHub API until you unlock the store.** git push and pull are not affected because they
use SSH.

- Run `mise run gw:unlock` **every time** the gateway is recreated or restarted. The key
  exists only in memory.
- `whoami`, `check` and `logout` now require the relay to be running, because they use its
  control socket.
- The relay moves an existing `/data/relay/upstream_token` into the store the first time
  it reads the file, and then deletes the file. **No manual step is required.**

If you skipped 0.2.15, you cannot proceed here: you have no `gw:unlock`, and a
`gw:unlock` that you add does not work without `gw-tty`. Complete the 0.2.15 section first.

The same release refuses a push that moves a tag that the upstream already advertises.
**Creating a new tag is not affected**, so your release process does not change.

## 0.2.20 tasks come from the gateway now

**This step is optional, but doing it once is recommended.** The image contains its own
`gw:*` tasks, so a project no longer needs to keep a copy of them.

The sample (`examples/sgw-sample/`) already uses this layout, so a new project can start
from it. For an existing project, add `gw:sync-tasks` and run it once:

```toml
# mise.toml — the one task you keep. It cannot come from the image, because it is the task that fetches from the image
[tasks."gw:sync-tasks"]
description = "Pull the gw:* tasks out of the running gateway (after gw:recreate)"
run = "bash \"$SGW\" gw cat /usr/local/share/sekimore/gateway.mise.en.toml > \"$MISE_PROJECT_ROOT/.devcontainer/gateway.mise.toml\" && echo wrote"
```

```bash
mise run gw:sync-tasks      # .ja.toml also works; the only difference is what `mise tasks` prints
```

```toml
# mise.toml — delete the gw:* tasks and keep your own
[task_config]
includes = [".devcontainer/gateway.mise.toml"]

[env]
SGW = "{{config_root}}/.devcontainer/scripts/sgw.sh"
```

Extract the tasks again after each `mise run gw:recreate`. The tasks then always match the
running gateway. This prevents the drift that made the 0.2.15 and 0.2.19 upgrades above
easy to get wrong.

You still own `sgw.sh`, and it must still contain `gw-tty`. The header of the shipped task
file lists the four `sgw.sh` primitives that the tasks use.

**Commit the extracted file.** `mise` **silently ignores a missing include file**, with no
error and no warning. If you add the file to `.gitignore`, none of the `gw:*` tasks exist
for the next person who clones the repository, and nothing reports it. Committing the file
also makes a gateway upgrade visible in `git diff`, which is the only place where it is
visible.

## 0.2.22 the proxy credential moved into the store

**This section applies only to a gateway behind a corporate proxy that requires a
password.** If your gateway is not behind such a proxy, no action is required.

The dev container can read `upstream_proxy_username` and `upstream_proxy_password` in
`config.yml`, and the `SEKIMORE_UPSTREAM_PROXY_*` variables: `config.yml` is in the
worktree, and `.devcontainer/.env` is the agent's own `env_file`. Store the credentials in
the secret store instead:

```bash
mise run gw:proxy-credential -- set     # prompts for the username and password on the terminal
```

Then remove the two keys from `config.yml` and the two variables from the place where you
set them, and run `mise run gw:recreate`. If you leave them in place, the gateway **still
reads them**, so this is not a breaking change. However, only removing them closes the
exposure.

Because the store is sealed at start-up, two things follow:

- Squid runs **without** upstream authentication until you run `mise run gw:unlock`, and
  picks up the credentials automatically once the store is unlocked. The gateway still
  starts behind a proxy that rejects anonymous requests, because no gateway traffic goes
  through the proxy before the store is unlocked.
- `gw:proxy-credential` is a gateway task. It becomes available through the include
  ([0.2.20](#0220-tasks-come-from-the-gateway-now)) after you run `mise run gw:sync-tasks`.

0.2.21 and 0.2.23 – 0.2.26 require no action.

## 0.2.27 tags have to be signed

**This section applies only to a project whose `tags:` globs allow the agent to push
tags.** For any other project, no action is required.

A pushed tag must now be an annotated tag object that carries a signature, created with
`git tag -s` in any format that git supports (OpenPGP, SSH or X.509). The relay refuses a
lightweight tag (`git tag v1`) and an unsigned annotated tag (`git tag -a`) with
`[remote rejected]` and a message that states the reason. The relay checks that a signature
is *present*, not who made it.

The dev container already signs tags: `agent-setup.sh` sets `tag.gpgsign true` with the
agent's SSH signing key, so both `git tag -s` and a plain `git tag -a` produce signed tags
there. The check catches a tag that bypasses this setup, for example one made with
`-c tag.gpgsign=false` or from a shell without the setup. The gateway's own first `v0.2.18`
tag was pushed in this way.

To disable the check, add one line at any configuration layer:

```yaml
# .devcontainer/config/config.yml
relay:
  project:
    signed_tags: false          # or under upstreams.<domain>, or on one entry of repos[]
```

Then run `mise run gw:recreate`. `mise run gw:check` shows the effective value for each
repository (`signed_tags=true|false`).

0.2.23 – 0.2.26 require no action.

## 0.2.28 Dependabot alerts are optional

**No action is required unless you want to use Dependabot alerts.** This release adds two
permission keys: `security:read` (list and view the repository's Dependabot alerts) and
`security:dismiss` (dismiss an alert with a reason, or reopen it). No existing
configuration grants either key.

To enable them:

```yaml
# .devcontainer/config/config.yml
relay:
  project:
    permissions:
      - security:read
      # - security:dismiss      # hiding a vulnerability is a separate authority; grant it deliberately
```

Then run `mise run gw:recreate`, **and run `mise run gw:login` again**. The alerts API
requires the `security_events` OAuth scope, which logins before 0.2.28 did not request.
Without that scope, `sekimore security alerts` receives a 403 response from GitHub.

## 0.2.29 unattended unlock is available

**No action is required unless you want unattended unlock.** `mise run gw:unlock` is
unchanged, and a host that stores no passphrase behaves exactly as before.

Run `mise run gw:sync-tasks` to get the two new tasks. Then run the following once on each
host:

```bash
mise run gw:keychain-set     # prompts for the passphrase and stores it in this host's keychain
```

After that, `mise run gw:recreate` unlocks the store automatically. After a
`docker restart`, run `mise run gw:unlock-auto` to unlock the store without typing the
passphrase.

The tasks look for the passphrase in the following locations, in this order. `<project>` is
the name of the directory that `MISE_PROJECT_ROOT` points to, so two projects on one host
have separate entries.

| Host | Location | What ties the passphrase to this machine |
|---|---|---|
| macOS | Keychain, service `sekimore-gw`, account `<project>` | Your login. The keychain is locked until you log in. |
| Linux desktop | Secret Service (`secret-tool`), `service=sekimore-gw project=<project>` | Your login session |
| Server | `/etc/sekimore/<project>.passphrase.cred`, read with `systemd-creds decrypt` | The TPM or the host key. A copy of the disk does not contain a usable passphrase. |
| Server, last resort | `/etc/sekimore/<project>.passphrase`, owned by root, mode 0600 | **Nothing.** Anyone who can read the file has the passphrase. |

On a host that has neither keychain, `gw:keychain-set` prints the exact commands for the
two server options. Keep the mode of `/etc/sekimore` itself at 0755: the task uses
`sudo -n` only after it finds the file without sudo, and it never prompts for a sudo
password, because `gw:recreate` must not hang while it waits for one.

This `/etc/sekimore` is on the **host**. The gateway has a directory with the same name
inside its container (its `config.yml` is there). Do not mount the host's directory into
the gateway: doing so would give the gateway the passphrase that this design keeps away
from it.

This release does **not** change two things:

- The gateway learns nothing new. The host reads the passphrase and pipes it into
  `sekimore-relay unlock --stdin`. The passphrase still arrives over the control socket,
  which the dev container does not mount, and nothing inside the gateway can search for it.
  The passphrase is still the only protection for an export.
- You still type the first passphrase. `unlock --stdin` refuses a store that has never been
  initialized, because you choose the first passphrase rather than recall it, and the
  prompt asks for it twice.

To keep the gateway locked after a recreate, on one host or on all hosts, run:

```bash
SGW_NO_AUTO_UNLOCK=1 mise run gw:recreate
```

To look for the passphrase file in a directory other than `/etc/sekimore`, set
`SGW_PASSPHRASE_DIR`.

## 0.2.29 one signing key per person

**This step is optional, and nothing changes if you skip it.** Without
`relay.signing_key`, the dev container generates its own signing key as before.

The generated key is disposable, but a signing key must not be. You register a signing key
with GitHub by hand, and deleting it removes the Verified badge from every commit it has
signed. If the keys volume is wiped, the key is not regenerated; it is lost, and every
later commit is signed by a key that GitHub does not know. Nothing reported this, because
`commit.gpgsign` was set unconditionally and nothing checked whether the key was
registered.

To adopt the replacement (one key per person, registered once):

1. Create the key on your machine if you do not already have one for this purpose. **Do
   not use your own signing key**: a separate key keeps AI commits distinguishable in the
   history.

   ```bash
   ssh-keygen -t ed25519 -C "sekimore AI signing key" -f ~/.ssh/sekimore_signing
   ssh-add ~/.ssh/sekimore_signing          # add --apple-use-keychain on a Mac
   ssh-keygen -lf ~/.ssh/sekimore_signing.pub   # prints the SHA256:… fingerprint
   ```

2. Register the **public** key with GitHub once: Settings → SSH and GPG keys →
   New SSH key → Key type: **Signing Key**.

3. Add the fingerprint to `.devcontainer/config/config.yml`:

   ```yaml
   relay:
     signing_key:
       fingerprint: "SHA256:…"     # from step 1
   ```

   Your other keys can stay in the same agent. The relay gives the dev container a
   *filtered* socket that responds only for this fingerprint and signs nothing except git
   signatures. The other keys remain invisible, and the socket cannot be used for
   authentication.

4. Add the socket's volume to **both** services in
   `.devcontainer/docker-compose.relay.yml` (the sample already contains it):

   ```yaml
   services:
     sekimore-gw:
       volumes:
         - sekimore-signing:/run/sekimore
     dev:
       volumes:
         - sekimore-signing:/run/sekimore

   volumes:
     sekimore-signing:
       name: sekimore-signing-${DEVCONTAINER_ID}
   ```

5. Run `mise run gw:recreate`, and then run Rebuild Container. Confirm that the key is in
   use:

   ```bash
   mise run gw:check     # prints "signing key: in the host agent (…)"
   ```

   Inside the dev container, `ssh-add -l` now lists **exactly one** key: the signing key,
   through the filtered socket. If your `mise.toml` contains the 0.1.x `relay:verify`
   task, which fails when `ssh-add -l` succeeds, replace that block with the following:

   ```bash
   echo "== dev: only the gateway's filtered signing key may be reachable"
   n=$(bash "$SGW" dev ssh-add -l 2>/dev/null | grep -c . || true)
   if [ "$n" = 1 ]; then
     echo "OK: exactly one key (the signing key, via the gateway's filtered agent)"
   elif [ "$n" = 0 ]; then
     echo "OK: no ssh-agent in dev"
   else
     echo "❌ FAIL: ssh-add -l lists $n keys inside dev — the operator's keys are exposed to the AI. Reopen with: mise run vscode"
     fail=1
   fi
   ```

The old `~/.ssh/sekimore/signing_ed25519` is not deleted. It signed commits that are in the
history, and its public key must stay registered with GitHub for those commits to keep
their Verified badge.

**`signing: required`** is a separate, optional setting. With it, the relay refuses a push
to a branch if any commit in the push has no signature. This check would have detected the
unregistered-key problem twenty commits earlier. The default is `optional`, so the
behavior of existing projects does not change.

```yaml
relay:
  project:
    signing: required     # or per upstream, or per repos[]
```

Enable it only after step 5 succeeds: if you enable it without a key, the relay refuses
every push.

`required` also **requires the upstream API**. At the point where the pushed history leaves
the pack, the relay asks the upstream whether it already has that commit. Without this
query, a commit hidden behind a delta cannot be distinguished from inside the pack. The
gateway must therefore be unlocked (`mise run gw:unlock`) and logged in. Otherwise, pushes
fail closed, and the message states which condition is missing.

## 0.2.37 the gateway needs pid: host

**Every project must act.** Until now, the agent was confined only inside the containers. A
root process in dev could run `ip route replace default via <bridge .1>` and leave through
Docker's own NAT, around every filter the gateway runs. From 0.2.37, the gateway adds two
FORWARD rules to the host's `DOCKER-USER` chain: traffic from the internal bridge may stay
on that bridge, where the gateway is, and anything leaving it is dropped. The gateway
enters the host's namespaces with `nsenter` to add them, so it needs the host's PID
namespace.

Add `pid: host` to the `sekimore-gw` service in `.devcontainer/docker-compose.yml` (the
sample already contains it). Do not add it to `dev`.

```yaml
services:
  sekimore-gw:
    privileged: true
    pid: host                 # the FORWARD rules that confine dev live in the host's DOCKER-USER chain
```

Then run `mise run gw:recreate`. Without `pid: host` the gateway still starts, but the agent
is **not** confined.

To confirm that the rules are in place, read the gateway's log:

```bash
docker logs "$(bash .devcontainer/sgw/sgw.sh id sekimore-gw)" 2>&1 | grep 'FORWARD enforcement'
```

It prints "Host-side FORWARD enforcement in place". Without `pid: host`, it prints
"Host-side FORWARD enforcement is not in place" and the reason.

`mise run relay:verify` also checks the bypass itself: from dev, it adds a host route
through the bridge's own router and expects the connection to fail.

0.2.30 – 0.2.36 require no action.

## 0.2.44 a ProxyJump bastion's host key has to be known

**This section applies only if an upstream in `config.yml` has `ProxyJump` in its
`relay.ssh_options`.** Without a bastion there is nothing to do.

Until now the jump hop was reached with whatever the relay's ssh defaults allowed. From 0.2.44
every hop, the bastion included, is verified with `StrictHostKeyChecking yes` against the
upstream's known_hosts. A bastion whose key is not there no longer prompts and no longer passes:
git through the relay fails closed, with the keyscan command to run.

Run one of the following once after `mise run gw:recreate`:

```bash
mise run gw:login          # fetches the missing bastion keys, shows the fingerprints, asks yes/no
```

or, to take the keys without logging in again:

```bash
docker compose exec sekimore-gw sekimore-relay keyscan <bastion> --port <port>
docker compose exec sekimore-gw sekimore-relay keyscan <upstream-host> --port <port> --upstream <domain>
```

The second one goes through the bastion, so run it after the first.

0.2.38 – 0.2.43 require no action. Neither does [0.2.46](#0246-the-base-image-moved-into-sekimore-gw); it only says where the files come from now. [0.2.47](#0247-sgw-is-available) requires no action either; it only adds `sgw` beside the mise tasks. Nor does 0.2.48; it only fills in what 0.2.47 promised.

## 0.2.45 `gw:login` asks on a terminal and stops without a host key

**This section applies only if an upstream in `config.yml` needs a host key the gateway has not
saved yet** — a `ProxyJump` bastion, or an upstream whose key was never scanned.

`gw:login` now takes the host keys it needs before the device flow and asks yes/no on a terminal.
When a key it needs was not saved — the question was declined, there was no terminal, or the scan
failed — the login stops with a non-zero exit instead of handing out a token git cannot use.

Run `mise run upgrade:apply` to get the new task file, then `mise run gw:login` again.

To skip the question, take the keys first:

```bash
mise run gw -- keyscan <bastion> --port <port> --upstream <domain>
mise run gw -- keyscan <upstream-host> --port <port> --upstream <domain>
```

The second one goes through the bastion, so run it after the first.

## base 0.2.19 `mise run web` finds the port itself

**If you are upgrading to base 0.2.20, skip this section.** The
[base 0.2.20 section](#base-0220-devcontainersgw-and-mise-run-upgrade) replaces both files
completely.

**This step is optional.** Nothing breaks if you skip it until you change the Web UI's
published port. After that change, the old `web` task opens the wrong address.

The old task contained the port as a literal, but the compose file determines the actual
port. A project where port 8090 is already in use changes the published port, the task
still opens the old port, and `mise run web` reaches nothing, or, worse, another project's
gateway.

This change is not tied to a gateway version. It affects only the sample's own files; the
gateway is unchanged.

Copy both files from the sample. `sgw.sh` gains a `port` branch, and the `web` task in
`mise.toml` calls it:

```bash
diff -u <base>/examples/sgw-sample/.devcontainer/scripts/sgw.sh .devcontainer/scripts/sgw.sh
diff -u <base>/examples/sgw-sample/mise.toml mise.toml
```

After that, `mise run web` prints the URL that it opens, so a wrong port is visible instead
of failing silently.

## base 0.2.20 `.devcontainer/sgw/` and `mise run upgrade`

**Do this once, by hand. After that, run `mise run upgrade:apply` to upgrade.**

The host scripts and tasks move into `.devcontainer/sgw/`, which you no longer own.
`mise run upgrade:apply` replaces the directory completely, and stops instead of
overwriting a file in it that was edited by hand. `mise.toml` keeps only the includes and
your own tasks.

1. If `FROM` uses `latest`, pin the base image to a version. `upgrade` reads the base and
   gateway image tags and cannot update a `latest` tag:

   ```dockerfile
   FROM ghcr.io/amakata/sgw-devcontainer-base:0.2.20
   ```

2. Download `upgrade.sh` and run it to add the remaining files:

   ```bash
   mkdir -p .devcontainer/sgw
   curl -fsSL -o .devcontainer/sgw/upgrade.sh \
     https://raw.githubusercontent.com/Amakata/sgw-devcontainer-base/v0.2.20/share/sgw/upgrade.sh
   bash .devcontainer/sgw/upgrade.sh --sync
   ```

   The script prints the includes that `mise.toml` must contain and the old files that are
   no longer used.

3. Remove everything except your own tasks from `mise.toml`. **Delete the tasks that are
   now distributed**: `vscode`, `vscode:check`, `vscode:restore-agent-env`, `web`, `ps`,
   `down`, `dev:*`, `relay:verify` and `gw:sync-tasks`. A task in `mise.toml` overrides the
   distributed task with the same name, so a stale copy would hide every later fix to that
   task. Keep your own tasks, and add the following:

   ```toml
   [task_config]
   includes = [".devcontainer/sgw/tasks.mise.toml", ".devcontainer/sgw/gateway.mise.toml"]

   [env]
   SGW = "{{config_root}}/.devcontainer/sgw/sgw.sh"
   ```

4. Remove the old layout:

   ```bash
   git rm .devcontainer/scripts/sgw.sh .devcontainer/scripts/vscode.sh .devcontainer/gateway.mise.toml
   ```

5. Run `mise run upgrade`. It should list the versions and report that everything is up to
   date.

`gw:sync-tasks` no longer exists: `mise run upgrade:sync` fetches the gateway's tasks
together with the other distributed files. The task descriptions and the scripts' output
follow `LC_ALL` / `LC_MESSAGES` / `LANG`. To fix the language, set `SEKIMORE_LANG = "ja"`
(or `"en"`) under `[env]`, and then run `mise run upgrade:sync`.

## base 0.2.22 `postStartCommand` runs `.devcontainer/sgw/post-start.sh`

**Change one line in `devcontainer.json`, once.** `mise run upgrade` reports this step
until you complete it.

```json
"postStartCommand": "sh /workspace/.devcontainer/sgw/post-start.sh",
```

`agent-setup` runs under `sudo`, which resets the environment. A variable from `.env`
therefore reached it only if `--preserve-env=` named the variable, and a variable missing
from that list was set but silently ignored. The list was in `devcontainer.json`, which you
own, and it fell behind each time agent-setup gained a new input (for example,
`SEKIMORE_GUIDE_LANG`). `post-start.sh` passes every `SEKIMORE_*` variable that the
container has, and then runs `docker-init.sh` and your
`.devcontainer/scripts/post-create.sh`, as the old line did. Move any other command that you
ran in `postStartCommand` into `post-create.sh`.

You can also delete any comment in `.env` that tells you to add a variable to
`--preserve-env=`.

## base 0.2.26 the credential helper is `post-start.sh`'s

**This step is required if your `post-create.sh` contains
`disable_vscode_credential_helper`: the container fails to start every time until you
remove it.**

On every start, `.devcontainer/sgw/post-start.sh` now removes the HTTPS credential helper
that the VS Code extension writes into `/etc/gitconfig` and `~/.gitconfig`, before your
`post-create.sh` runs. `SEKIMORE_ALLOW_CREDENTIAL_HELPER=1` still keeps the helper.

A project created from an older sample contains `disable_vscode_credential_helper` in its
own `.devcontainer/scripts/post-create.sh`. Delete the function and its call. From base
0.2.29, `post-start.sh` prints a warning about it on every start, but the start still fails
until you remove the copy. The copy is not merely redundant: it ends with
`[ "$changed" = 1 ] && echo …`, which returns 1 when there is nothing to remove. Under
`set -e`, that return value stops `post-create.sh` and therefore the container's start. In
addition, the sample's copy changed `/etc/gitconfig` without sudo, so it never removed the
system-level helper.

## base 0.2.28 `gh` is gone

**This section applies only if something that you run calls `gh`.**

The GitHub CLI is no longer in the image. It reached `api.github.com` through the relay's
443 passthrough, which forwards traffic without reading the requests. A `gh` with a token
could therefore act on GitHub without any of the per-action permissions that the relay
enforces. For example, denying `pr:merge` in `config.yml` did not stop `gh pr merge`, and
`gh` could also act on repositories outside the project.

`sekimore` performs the same operations through the agent API, where the relay checks each
action against the project configuration and records it:

| Instead of | Use |
|---|---|
| `gh pr create` | `sekimore pr create --head <branch> --base <base> --title T --body="…"` |
| `gh pr merge` | `sekimore pr merge --number N` |
| `gh pr view` / `gh pr checks` | `sekimore pr status --number N` |
| `gh issue create` | `sekimore issue create --title T` |
| `gh run view` / `gh run view --log` | `sekimore ci jobs --number N` / `sekimore ci log --number N` |
| `gh release create` | `sekimore release create --tag vX.Y.Z` |

`sekimore guide` lists the other commands. If one of your own scripts requires `gh`,
install `gh` where that script runs. Note that the relay cannot see or refuse anything that
`gh` does.

## base 0.2.40 the dev container learns about the upstream proxy

**This section applies only if `config.yml` sets `proxy.upstream_proxy`.**

Until now nothing in dev knew about the upstream proxy, so ordinary traffic — `curl`, `pip`,
`npm`, a language runtime — left directly instead of going through the gateway's Squid and out
through the proxy. The gateway now writes the proxy's environment, and dev picks it up:

- the gateway writes `/etc/profile.d/sekimore-proxy.sh`, and the same block in `/etc/environment`
  between `# sekimore-proxy begin` and `# sekimore-proxy end`, with `HTTP_PROXY`, `HTTPS_PROXY`,
  `NO_PROXY` and their lowercase twins. `NO_PROXY` lists the `domain_handlers` targets, your own
  `proxy.no_proxy`, `localhost`, `127.0.0.1` and `sekimore-gw`
- base 0.2.40 adds `/etc/skel/zsh-rc.d/10-sekimore-proxy.zsh`, which sources that file. Debian's
  zsh does not read `/etc/profile.d`, and Claude Code and `docker exec` run non-login shells, so
  the rc.d snippet is what makes every shell in dev see it

**If a project already sets its own `HTTP_PROXY`** — in `devcontainer.json`, in the compose file,
in `post-create.sh` or in its own zsh rc.d — remove it, or keep it in step with the gateway's.
Two different values is the failure that is hard to see: one process reaches the proxy and the
next does not. A snippet numbered after `10-` still wins, so a deliberate override keeps working.

What to do:

```bash
mise run gw:recreate       # the gateway writes the files
```

Then **Rebuild Container** (`Dev Containers: Rebuild Container` in the VS Code command palette),
which is what brings in the rc.d snippet: post-create copies `/etc/skel/zsh-rc.d/` only on a create.

How to tell:

```bash
env | grep -i proxy        # in dev: HTTP_PROXY, HTTPS_PROXY, NO_PROXY and the lowercase ones
mise run relay:verify      # on the host
```

`relay:verify` gained `== dev: the upstream proxy is used for ordinary traffic`. It says `SKIP`
when no upstream proxy is configured, and also when the gateway is too old to report its egress
policy — that gateway writes no `HTTPS_PROXY` either, so there is nothing yet to check. Otherwise
it checks that dev has `HTTPS_PROXY`, and that a request that goes around it (`curl --noproxy '*'`)
to an `allow_domains` host fails. If that request succeeds while `proxy.direct_egress` is `deny`,
it is a **FAIL**: dev can leave without the proxy. While `direct_egress` is `allow` it is a
warning, not a failure.

## 0.2.46 The base image moved into sekimore-gw

Nothing to do. The dev-container base image (`ghcr.io/amakata/sgw-devcontainer-base`) is built
from `base/` of the sekimore-gw repository and released from the same tag, so from 0.2.46 on the
base carries the gateway's version number (the base went 0.2.43 → 0.2.46; 0.2.44 and 0.2.45 of the
base do not exist). `mise run upgrade` shows both moving together.

The distributed files (`.devcontainer/sgw/`) now come from `base/share/sgw/` of that repository,
and this guide from its root. An `upgrade.sh` from 0.2.43 or earlier still looks in the former
`Amakata/sgw-devcontainer-base` repository; that repository is archived, but carries a `v0.2.46` tag
holding the new files, so `mise run upgrade:apply` crosses over once and reads from the new place
from then on.

## 0.2.47 sgw is available

Nothing to do. The mise tasks keep working exactly as before; this release takes nothing away.

What is new is `sgw`, the operator's tool on the host, released as a binary beside them. It can be
installed next to the tasks and used from the project directory:

```bash
curl -fsSL https://github.com/Amakata/sekimore-gw/releases/latest/download/install.sh | sh
```

```bash
sgw check       # the relay's configuration and state
sgw verify      # the project's acceptance check
sgw unlock      # unlock the secret store
sgw recreate    # pull the image and re-create the gateway
sgw --help      # every subcommand
```

`init` and `update` are not in this release; a project is still set up and upgraded with the mise
tasks. From 0.2.48 the Release carries the binaries, so the install line above works, and
`sgw init` / `sgw update` exist.

## 0.2.51 postStartCommand is one line: sgw-post-start

**Every project: one line in `.devcontainer/devcontainer.json`.** The dev container's start-up
moved into the image. `sgw-agent setup` (agent-setup.sh ported to the relay's binary, #257) does
what the script did — DNS and the route to the gateway, the proxy environment, the keys, the
project token, known_hosts, `~/.ssh/config`, git's signing settings, the agent guide, the VS Code
credential helper taken out — and `sgw-post-start` runs it as root with the whole environment,
then `docker-init.sh`, then the project's `post-create.sh`. So `postStartCommand` is:

```json
"postStartCommand": "sgw-post-start",
```

`sgw update` names the line when it is missing. A project that keeps
`sh /workspace/.devcontainer/sgw/post-start.sh` still starts: on this base that script hands over
to `sgw-post-start`. `.devcontainer/sgw/post-start.sh` can go once the line is changed.

Nothing else changes for a project. `sekimore` keeps working as the former name of `sgw-agent`.
Rebuild Container after moving the base pin, as always when the base changes.

## 0.2.52 The mise layer is gone; `sgw update --apply` removes it

**Every project: run `sgw update --apply`, then commit.** The host-side mise tasks
(`.devcontainer/sgw/`: `tasks.mise.toml`, `gateway.mise.toml`, `sgw.sh`, `upgrade.sh`,
`vscode.sh`, `post-start.sh`, `MANIFEST`) are no longer distributed. Everything they did is a
`sgw` command (`sgw --help`). `sgw update --apply` on this version:

- removes `.devcontainer/sgw/` (only when it holds nothing but those files)
- takes the `includes` of `.devcontainer/sgw/` and the `SGW` line out of `mise.toml`; your own
  tasks stay. When nothing of yours is left, it says so: `git rm mise.toml`
- makes `postStartCommand` the one line `sgw-post-start` when it still named
  `.devcontainer/sgw/post-start.sh` (that file is gone)
- writes `sgw.toml` beside `.devcontainer/`: sgw's record of the template files as it wrote them,
  so later updates can tell a file you edited from one a new version changes

`mise run …` no longer exists on the host. The dev container's own `mise` is untouched.

