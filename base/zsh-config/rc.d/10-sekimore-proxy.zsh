# sekimore-gw: the upstream proxy's environment, written by sekimore-agent-setup.sh
#
# With `proxy.enabled` and `upstream_proxy` in config.yml, agent-setup (which post-start.sh runs
# as root on every start) writes /etc/profile.d/sekimore-proxy.sh with HTTP_PROXY / HTTPS_PROXY /
# NO_PROXY and their lowercase twins, and the same block in /etc/environment between
# `# sekimore-proxy begin` and `# sekimore-proxy end`. Without an upstream proxy neither exists,
# and this file does nothing.
#
# Why here rather than relying on /etc/profile.d alone: Debian's /etc/zsh/zprofile does not read
# /etc/profile.d, so not even a zsh LOGIN shell would pick it up — and Claude Code, `docker exec`
# and the AI's tool subprocesses run non-login shells, which never read a profile at all. rc.d is
# the one path every shell in dev goes through. /etc/environment is PAM's, and covers logins;
# it is not touched here.
#
# Early (10-) so that everything after it — mise, aliases, plugins, and whatever the project adds —
# already sees the proxy. A project that sets its own HTTP_PROXY in a later snippet still wins.
if [ -r /etc/profile.d/sekimore-proxy.sh ]; then
  . /etc/profile.d/sekimore-proxy.sh
fi
