# A Linux host over Remote-SSH

*[日本語版](remote-ssh.ja.md)*

VS Code on a Mac, Remote-SSH to a Linux VM, Dev Containers on the VM. The aim is the same as
on the Mac: the operator's ssh-agent reaches the gateway, and does not reach the dev container.

- The Mac's agent is carried to the VM by `RemoteForward` into a fixed path, which the gateway mounts.
- Agent forwarding (`SSH_AUTH_SOCK`) is off for every connection VS Code makes. The Dev Containers
  extension forwards whatever `SSH_AUTH_SOCK` the VS Code server holds, and the server keeps the
  environment of its first start across reconnects.

## Mac

`~/.ssh/config`: one Host for the terminal, one for VS Code.

```
Host devvm
  HostName 192.168.56.11
  User dev
  ForwardAgent yes

Host devvm-vscode
  HostName 192.168.56.11
  User dev
  ForwardAgent no
  RemoteForward /home/dev/.sekimore/agent.sock ${SSH_AUTH_SOCK}
  ControlMaster auto
  ControlPath ~/.ssh/cm-%r@%n:%p
  ControlPersist 10m
```

- `${SSH_AUTH_SOCK}` is expanded by ssh when it connects (OpenSSH 8.4 and later). The launchd
  path changes on every login, so do not write it out.
- `ControlMaster` keeps one connection: two sessions asking for the same `RemoteForward` would
  each own the socket, and the first to close would take it away.
- Every connection VS Code makes goes through `devvm-vscode` (`code --remote ssh-remote+devvm-vscode …`).
  Connecting once through `devvm` leaves the server with `SSH_AUTH_SOCK` for as long as it runs.
- Start VS Code the ordinary way, not with `sgw open`: `sgw open` removes `SSH_AUTH_SOCK` from
  the app, and then `${SSH_AUTH_SOCK}` has nothing to expand.

VS Code's `settings.json`:

```json
"remote.SSH.enableAgentForwarding": false
```

VS Code adds `-A` to its ssh command line unless this is off, and a command-line option beats
the config file.

## VM

```
mkdir -m 700 ~/.sekimore
printf 'Host *\n  IdentityAgent ~/.sekimore/agent.sock\n' >> ~/.ssh/config
echo 'StreamLocalBindUnlink yes' | sudo tee -a /etc/ssh/sshd_config
sudo sshd -t && sudo systemctl restart ssh
```

- `StreamLocalBindUnlink` lets sshd replace the socket file on every reconnect.
- `IdentityAgent` gives `ssh` and `git` on the VM the Mac's keys without an environment variable
  that the VS Code server could inherit. Do not export `SSH_AUTH_SOCK` in `.bashrc` / `.zshrc`.
- To look: `SSH_AUTH_SOCK=~/.sekimore/agent.sock ssh-add -l`.

## The project

`.devcontainer/.env`: the **directory**, not the socket.

```
SEKIMORE_AGENT_SOCK=/home/dev/.sekimore
```

The gateway mounts it and reads `agent.sock` inside by name on every connection, so a socket
that sshd recreates is picked up without `sgw recreate`. Naming the socket file itself works
too, but a file bind-mount keeps the inode the container started with: after every reconnect
the gateway talks to a dead socket until `sgw recreate`, and a path that does not exist when
the gateway starts becomes a directory Docker made.

## Bringing it up

1. Run "Remote-SSH: Kill VS Code Server on Host" once, so the server forgets the environment it started with.
2. Connect from the Mac and check the socket is there:
   ```
   ssh devvm-vscode 'SSH_AUTH_SOCK=~/.sekimore/agent.sock ssh-add -l'
   ```
3. On the VM: `sgw recreate`, then `sgw check` (ssh-agent: N identities) and `sgw verify`.
   The `host:` items say whether the socket answers and whether a VS Code server carries `SSH_AUTH_SOCK`.
4. Reopen the project in the container. post-create passes, and `echo $SSH_AUTH_SOCK` in the
   VS Code terminal on the VM is empty.
