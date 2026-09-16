# sekimore-relay — guide for AI agents

In this environment every git operation and every GitHub API call goes through a relay (sekimore-relay).
Start with `sekimore whoami` to see your project, your permissions and the repositories you may touch.

## Ground rules

- You hold three things: a disposable SSH key, a signing key for AI commits and a project token. The operator's own keys and tokens are not in this environment. Do not look for them.
- Only repositories registered for the project are reachable. Denials are printed on stderr as `sekimore: …`, and the reason tells you what to do next.
- Traffic leaving the relay is limited (upload size, destination ports) and fully audited. Do not try to work around it. Attempts are recorded and visible to the operator.
- The project token expires. The `sekimore` command renews it automatically. If renewal fails, ask a human to run agent-setup again.

## git

- clone / fetch / pull work with the plain URL: `git clone git@github.com:Org/Repo.git`
- There are only two push targets.
  - `git push origin HEAD:refs/for/<base>` puts the commits on a branch named `sekimore/<base>-<sha7>` and opens a pull request against `<base>` automatically. The title is generated, so use the other form when you want to write the title and body yourself.
  - `git push origin HEAD:refs/heads/sekimore/<topic>` is a working branch. Open the pull request with `sekimore pr create`. This is the recommended path.
- Direct pushes to `main`, tags, branch deletions and force pushes are refused by default. They work only for repositories where they are allowed; check with `sekimore whoami`.
- Commits are signed automatically with the AI signing key. Do not change the signing configuration.
- The HTTPS URL of a repository (`https://github.com/…`) cannot be used for push or clone. Use the SSH URL.

## Pull requests, CI and issues (the `sekimore` command)

You may only use the operations listed under `permissions` in `sekimore whoami`. Anything else is refused with 403.

```bash
sekimore pr create --head sekimore/<topic> --base main --title "…" --body="…"
sekimore pr status --number N            # state of the CI checks (--json for machine output)
sekimore pr merge --number N             # when pr:merge is allowed
sekimore ci runs --ref <tag|branch|sha>  # workflow runs for a ref
sekimore ci jobs --number N              # jobs of the PR's latest run (which failed, job_id)
sekimore ci log --number N               # log of the failed job from the end; --before <start> pages back, --window sets the size
sekimore issue create --title "…" --body="…" [--labels a,b]
```

- Select the repository with `--repo Org/Repo`, or leave it to `SEKIMORE_REPO`. With several upstreams you can prefix the host: `--repo ghe.example.com/Org/Repo`.
- When the value of `--body` starts with `-`, always write it as `--body="…"`, otherwise it is read as an option.
- To wait for CI, poll `sekimore pr status --number N` every 30 seconds. On failure read `sekimore ci log --number N`, fix the cause and push again.

## The usual flow

1. Work on a branch and get the tests passing.
2. `git push origin HEAD:refs/heads/sekimore/<topic>`
3. `sekimore pr create --head sekimore/<topic> --base main --title "…" --body="…"`
4. Wait for `sekimore pr status --number N` to go green. Read `sekimore ci log` when it does not.
5. With the permission and a human's go-ahead, `sekimore pr merge --number N`. Tags are pushed with `git push origin vX.Y.Z` and only for repositories where tags are allowed.

## Common denials

| Message | Meaning | What to do |
|---|---|---|
| `repository "X" is not in project "P"` | the repository is outside the project | ask a human to add it |
| `X is read-only in project P` | read-only repository | reading only, no push and no PR |
| `push to refs/heads/main is not allowed` | no direct push | push to `refs/heads/sekimore/<topic>` and open a PR |
| `base branch X is not allowed` | no PR against that base | use an allowed base, see `sekimore whoami` |
| `tag is not allowed for this repository` | tags are refused | ask a human to tag, or to allow tags |
| `denied: pr:merge is not allowed by policy` | permission missing | ask a human to merge |
| `denied: token expired` | the project token expired | it renews itself; if it keeps failing ask a human to re-run agent-setup |

## What to ask a human for

- New repositories or permissions, and allowing a base branch or tags. These live in the gateway's config.yml and need the gateway to be recreated.
- Registering the signing key with GitHub, which is what makes commits show as Verified.
- Refreshing the upstream token (`sekimore-relay login`) or adding known_hosts entries.
