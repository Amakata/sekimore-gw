# sekimore-relay: export the project token / endpoint written by sekimore-agent-setup.sh
# so that git-adjacent tools and `sekimore-relay agent ...` work from interactive shells.
# (The `sekimore` wrapper does the same for non-interactive processes.)
if [ -r /etc/sekimore-agent/env ]; then
  set -a
  source /etc/sekimore-agent/env
  set +a
fi

# sekimore-relay guardrail: neutralise VS Code's git/ssh askpass so HTTPS git cannot borrow the
# operator's GitHub credentials from the host (VS Code injects GIT_ASKPASS + VSCODE_GIT_IPC_HANDLE,
# which git uses for HTTP Basic auth — a path that bypasses the relay). git@github.com goes through
# the relay's SSH and is unaffected. Set SEKIMORE_ALLOW_CREDENTIAL_HELPER=1 to keep the VS Code askpass.
# The other half — the credential.helper the extension writes into /etc/gitconfig and ~/.gitconfig —
# is taken out by .devcontainer/sgw/post-start.sh on every start (it needs sudo, and has to hold
# outside interactive shells too).
if [ "${SEKIMORE_ALLOW_CREDENTIAL_HELPER:-0}" != "1" ]; then
  export GIT_ASKPASS=""
  export SSH_ASKPASS=""
  unset VSCODE_GIT_ASKPASS_MAIN VSCODE_GIT_ASKPASS_NODE VSCODE_GIT_IPC_HANDLE VSCODE_GIT_ASKPASS_EXTRA_ARGS 2>/dev/null
fi
