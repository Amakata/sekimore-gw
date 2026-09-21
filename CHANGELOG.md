# sekimore-gw changelog

*[日本語版](CHANGELOG.ja.md)*

The gateway as a whole: DNS, the firewall, Squid, the Web UI, the build and CI.
The relay's own changes are in [relay/CHANGELOG.md](relay/CHANGELOG.md), under
the same version number — one image carries both.

Entries are grouped **Security**, **Fix**, **Enhancement** — most urgent first —
and say what changed, with the pull request that changed it. The reasoning is in
the pull request.

Starts at 0.2.18. Everything before it is in the relay's changelog, which
carried the whole project until the two were separated.

## 0.2.21 (2026-09-21)

### Enhancement

- dropped the release build cache: exporting it took 3m38s, longer than the 2m16s of build it could save, and #97 showed nothing read it (#101)
- normalised the layer timestamps to a fixed epoch, so a layer rebuilt to the same bytes keeps its digest and a release stops re-pulling 160 MB of identical content (#101)

## 0.2.20 (2026-09-21)

### Enhancement

- shipped the gateway's own `gw:*` mise tasks in the image, so a project includes them instead of copying them into its `mise.toml` (#95)
- added `gw:revoke`, which was reachable only as `mise run gw -- revoke --label …` (#95)
- checked in CI that every operator subcommand has a task, that both languages carry the same set, and that no task needs an `sgw.sh` primitive that does not exist (#95)

## 0.2.19 (2026-09-21)

### Security

- pinned the Debian archive to a `snapshot.debian.org` timestamp and every package to a version; `apt-get update` took whatever Debian served that day (#93)
- named `bind9-dnsutils` instead of `dnsutils`, which trixie has no package for — a virtual name has no version to pin (#93)

### Enhancement

- failed the build once the Debian snapshot is more than 90 days old, since no security update reaches the image between bumps (#93)

## 0.2.18 (2026-09-21)

### Security

- pinned every action to a commit and every base image to a digest, with the version kept as a comment (#87)

### Enhancement

- added `test_supply_chain_pins.py`, so a floating tag added later is an error rather than nothing (#87)
- split this changelog out of the relay's, which had been carrying the gateway's own changes as well (#88)
- pointed the README at both changelogs instead of naming a version, which had been seven releases stale (#88)
