//! Actions, images, Debian packages and the snapshot are pinned, and Dependabot reads every pin
//! (rules in `sekimore_tools::checks::pins`); then each rule on files broken on purpose.

use std::path::{Path, PathBuf};

use sekimore_tools::checks::pins::*;
use sekimore_tools::repo_root;
use serde_yaml_ng::Value;

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn name(p: &Path) -> String {
    p.file_name().unwrap().to_string_lossy().into()
}

/// (name, body) of each workflow.
fn workflow_bodies() -> Vec<(String, String)> {
    workflows(&repo_root())
        .iter()
        .map(|p| (name(p), read(p)))
        .collect()
}

fn image_files() -> Vec<(String, String)> {
    IMAGE_FILES
        .iter()
        .map(|f| (f.to_string(), read(&repo_root().join(f))))
        .collect()
}

fn dockerfiles() -> Vec<(String, String)> {
    image_files()
        .into_iter()
        .filter(|(f, _)| is_dockerfile(f))
        .collect()
}

fn dependabot() -> Value {
    serde_yaml_ng::from_str(&read(&repo_root().join(DEPENDABOT))).unwrap()
}

#[test]
fn it_has_workflows_to_check() {
    // A rename or a move would otherwise turn every test below green by having nothing to look at
    assert!(
        !workflows(&repo_root()).is_empty(),
        "no workflows found; this test is looking in the wrong place"
    );
    let missing: Vec<&str> = IMAGE_FILES
        .iter()
        .copied()
        .filter(|f| !repo_root().join(f).exists())
        .collect();
    assert!(missing.is_empty(), "image files gone: {missing:?}");
    assert!(dockerfiles().len() >= 3, "the Dockerfiles are found");
}

#[test]
fn it_pins_every_action_to_a_commit() {
    let floating: Vec<String> = workflow_bodies()
        .iter()
        .flat_map(|(n, b)| floating_actions(n, b))
        .collect();
    assert!(
        floating.is_empty(),
        "a tag moves under the workflow that uses it, so an action is pinned to the commit and the \
         version kept as a trailing comment — `uses: owner/repo@<sha40> # v1.2.3`. Resolve with \
         `git ls-remote https://github.com/owner/repo refs/tags/<tag>^{{}}` (the peeled sha, for \
         an annotated tag). Not pinned: {floating:?}"
    );
}

#[test]
fn it_pins_every_image_to_a_digest() {
    let floating: Vec<String> = image_files()
        .iter()
        .flat_map(|(n, b)| floating_images(n, b))
        .collect();
    assert!(
        floating.is_empty(),
        "a base image tag is re-pushed in place, so it is pinned by digest with the tag kept for \
         readability — `python:3.13-slim@sha256:…`. Not pinned: {floating:?}"
    );
}

#[test]
fn it_keeps_a_version_comment_a_human_can_read() {
    // The digest alone says nothing about how old it is. Dependabot reads this comment to know
    // what the pin was, and a person reads it to know whether the pin is three years stale.
    let bare: Vec<String> = workflow_bodies()
        .iter()
        .flat_map(|(n, b)| pins_without_a_version(n, b))
        .collect();
    assert!(
        bare.is_empty(),
        "pinned, but with no `# <version>` comment saying what it is: {bare:?}"
    );
}

#[test]
fn it_pins_the_debian_archive_to_a_snapshot() {
    // Naming package versions is not enough on its own: their ~100 transitive dependencies still
    // resolve against whatever Debian is serving today, and a named version is gone from the
    // archive within weeks of being superseded. The snapshot is what makes both hold.
    for (n, b) in dockerfiles() {
        if installs_debian_packages(&b) {
            assert!(
                pins_snapshot(&b),
                "{n}: `apt-get` reads whatever Debian serves today, so the layer gets a new digest \
                 on essentially every build. Point the sources at \
                 `https://snapshot.debian.org/archive/debian/<YYYYMMDDTHHMMSSZ>`."
            );
        }
    }
}

#[test]
fn it_pins_every_apt_package_to_a_version() {
    // The snapshot already fixes what gets installed. These make a change *loud*: bumping the
    // snapshot without noticing that squid moved is the failure this catches.
    let floating: Vec<String> = dockerfiles()
        .iter()
        .flat_map(|(n, b)| unpinned_packages(n, b))
        .collect();
    assert!(
        floating.is_empty(),
        "name the version — `squid=6.13-2+deb13u3`. Read them out of the snapshot itself, not out \
         of a running container. Not pinned: {floating:?}"
    );
}

#[test]
fn it_does_not_let_the_snapshot_go_stale() {
    // A pinned archive means no security update reaches the image until someone moves the pin.
    // That turns the bump from housekeeping into an obligation, so it is checked rather than
    // remembered. Widen MAX_SNAPSHOT_AGE_DAYS if the cadence is deliberately slower.
    let stale: Vec<String> = dockerfiles()
        .iter()
        .filter_map(|(n, b)| stale_snapshot(n, b, now()))
        .collect();
    assert!(stale.is_empty(), "{}", stale.join("\n"));
}

#[test]
fn it_configures_dependabot_at_all() {
    // Every pin above is written so that a machine can move it. From #87 until #103 none did.
    assert!(
        repo_root().join(DEPENDABOT).exists(),
        "the pins carry version comments and digests so that Dependabot can bump them, and without \
         .github/dependabot.yml nothing reads either — they are frozen, not maintained (#103)"
    );
    let config = dependabot();
    assert_eq!(
        config.get("version").and_then(Value::as_i64),
        Some(2),
        "Dependabot requires `version: 2`"
    );
    assert!(
        !dependabot_updates(&config).is_empty(),
        "the config has no `updates:` entries"
    );
}

#[test]
fn it_still_finds_the_pins_it_reads_the_ecosystems_from() {
    // The two checks below run over what the tree says is pinned. A derivation that quietly stops
    // finding anything would read as a clean run. Same reason as it_has_workflows_to_check.
    let found: Vec<&str> = ecosystems_with_pins(&repo_root()).into_keys().collect();
    assert_eq!(
        found, PINNED_ECOSYSTEMS,
        "the set of pinned ecosystems read off the tree changed. If that is deliberate, move \
         PINNED_ECOSYSTEMS and .github/dependabot.yml with it, in the same commit"
    );
}

#[test]
fn it_has_an_updater_for_every_pinned_ecosystem() {
    // A pin added to a new ecosystem is the failure this catches: nothing about adding a compose
    // file or a lockfile makes anyone remember this config exists.
    let config = dependabot();
    let configured: Vec<String> = dependabot_updates(&config)
        .iter()
        .filter_map(|u| u.get("package-ecosystem").and_then(Value::as_str))
        .map(String::from)
        .collect();
    for (ecosystem, what) in ecosystems_with_pins(&repo_root()) {
        assert!(
            configured.iter().any(|c| c == ecosystem),
            "pinned here: {what}. Nothing reads it — there is no `package-ecosystem: {ecosystem}` \
             in .github/dependabot.yml, so those pins are frozen rather than maintained. \
             Configured: {configured:?}"
        );
    }
}

#[test]
fn it_points_each_updater_at_the_files_it_reads() {
    // Dependabot reports a directory it found nothing in on its own page, which nobody here is
    // watching. Every entry is checked, not one per ecosystem: the same ecosystem may be listed
    // twice for two directories, and the broken one is as likely to be either.
    let config = dependabot();
    let problems: Vec<String> = dependabot_updates(&config)
        .iter()
        .enumerate()
        .flat_map(|(i, u)| updater_problems(&repo_root(), i, u))
        .collect();
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn it_clears_what_records_that_a_build_happened() {
    // An unchanged layer that gets a new digest makes every deployment re-pull it. Measured
    // between 0.2.21 and 0.2.22: the 160 MB apt layer differed by 114 bytes, and these seven files
    // were the whole of it — logs of the install, and ids generated per build. None is read by the
    // gateway. BuildKit's timestamp normalisation cannot help: the difference is the files'
    // contents, not their mtimes (#97).
    for (n, b) in dockerfiles() {
        let missing = residue_left(&b);
        assert!(
            missing.is_empty(),
            "{n}: these are written by the install and read by nothing, so leaving them gives the \
             layer a new digest every build: {missing:?}. Empty the machine-ids (absent is an \
             error for dbus and systemd; empty means 'generate at first boot') and remove the rest."
        );
    }
}

#[test]
fn it_ships_no_bytecode_and_writes_none() {
    // A .pyc carries its source's mtime inside the header, so any layer holding one gets a new
    // digest every build (#97). Two halves: nothing compiles during the build, and nothing writes
    // at runtime.
    let problems: Vec<String> = dockerfiles()
        .iter()
        .flat_map(|(n, b)| bytecode_problems(n, b))
        .collect();
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn it_does_not_ship_the_package_managers_cache() {
    // uv keeps every wheel it downloaded under /root/.cache/uv and it ends up in the layer: 1,195
    // files in the published 0.2.24 image.
    for (n, b) in dockerfiles() {
        let uncached = cached_installs(&b);
        assert!(
            uncached.is_empty(),
            "{n}: `uv pip install --no-cache`, or the wheels it downloaded ship with the image: \
             {uncached:?}"
        );
    }
}

#[test]
fn it_audits_both_halves_on_every_pull_request() {
    // `cargo audit` reads relay/Cargo.lock and nothing else, and for a while it was the only audit
    // a pull request ran. The green check was read as "the repository is clean" while the Python
    // side had 18 open alerts nobody was looking at (#75). Both lockfiles get a reader on every
    // pull request.
    let wf = workflow_bodies();
    for (tool, lockfile) in [
        ("cargo audit", "relay/Cargo.lock"),
        ("pip-audit", "uv.lock"),
    ] {
        assert!(
            !audited_on_pull_request(&wf, tool).is_empty(),
            "no workflow triggered by pull_request runs `{tool}`, so {lockfile} has no audit \
             before a change lands"
        );
    }
}

#[test]
fn it_installs_the_dependencies_without_the_project() {
    // `uv pip install .` writes sekimore_gw-<version>.dist-info, so that layer moved by a few bytes
    // every release with no dependency changed, and every deployment re-pulled it (#97).
    let problems: Vec<String> = dockerfiles()
        .iter()
        .flat_map(|(n, b)| project_install_problems(n, b))
        .collect();
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

// ---- each rule, on a file broken on purpose ----

const SHA: &str = "3d3c42e5aac5ba805825da76410c181273ba90b1";
const DIGEST: &str = "sha256:d8313491ec5798de0633fdc1c5753761bff79967bea69076020dc78121b2cca8";

#[test]
fn it_catches_an_action_on_a_tag() {
    let good = format!("steps:\n  - uses: actions/checkout@{SHA} # v7.0.1\n  - uses: ./local\n");
    assert!(floating_actions("x.yml", &good).is_empty());
    for bad in [
        "steps:\n  - uses: actions/checkout@v7\n",
        "steps:\n  - uses: actions/checkout@main # v7\n",
        "    uses: docker/build-push-action@3d3c42e5 # v7\n",
    ] {
        assert_eq!(floating_actions("x.yml", bad).len(), 1, "{bad}");
    }
}

#[test]
fn it_catches_a_pin_without_its_version_comment() {
    let bare = format!("  - uses: actions/checkout@{SHA}\n");
    assert_eq!(pins_without_a_version("x.yml", &bare).len(), 1);
    assert_eq!(floating_actions("x.yml", &bare).len(), 1);
}

#[test]
fn it_catches_an_unpinned_from() {
    let good = format!(
        "# syntax=docker/dockerfile:1.7@{DIGEST}\nFROM --platform=$BUILDPLATFORM golang:1.27@{DIGEST} AS build\nFROM build\nFROM scratch\n"
    );
    assert!(floating_images("Dockerfile", &good).is_empty());
    for bad in [
        "FROM python:3.14-slim\n",
        "FROM --platform=linux/amd64 ghcr.io/x/y:1\n",
        "# syntax=docker/dockerfile:1.7\n",
        "FROM debian:trixie@sha256:abc\n",
    ] {
        assert_eq!(floating_images("Dockerfile", bad).len(), 1, "{bad}");
    }
    assert_eq!(
        floating_images(
            "compose.yml",
            "services:\n  a:\n    image: python:3.11-slim\n"
        )
        .len(),
        1
    );
}

const APT: &str = "ARG DEBIAN_SNAPSHOT=20261120T000000Z
RUN echo \"deb https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} trixie main\" > /etc/apt/sources.list \\
    && apt-get update && apt-get install -y --no-install-recommends \\
        squid=6.13-2+deb13u3 \\
        ipset=7.23-1 \\
    && : > /etc/machine-id && : > /var/lib/dbus/machine-id \\
    && rm -f /var/log/alternatives.log /var/log/dpkg.log /var/log/apt/history.log /var/log/apt/term.log /var/cache/ldconfig/aux-cache
";

#[test]
fn it_catches_an_apt_package_without_a_version() {
    assert!(unpinned_packages("Dockerfile", APT).is_empty());
    assert_eq!(apt_packages(APT).len(), 2);
    let bad = APT.replace("ipset=7.23-1", "ipset");
    assert_eq!(
        unpinned_packages("Dockerfile", &bad),
        vec!["Dockerfile:5 ipset"]
    );
}

#[test]
fn it_catches_debian_sources_that_are_not_the_snapshot() {
    assert!(pins_snapshot(APT));
    let bad = APT.replace(
        "snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}",
        "deb.debian.org/debian",
    );
    assert!(installs_debian_packages(&bad) && !pins_snapshot(&bad));
}

#[test]
fn it_catches_a_stale_snapshot_date() {
    let stamped = parse_stamp("20261120T000000Z").unwrap();
    let day = 86_400;
    assert_eq!(
        stale_snapshot("Dockerfile", APT, stamped + 90 * day),
        None,
        "90 days is allowed"
    );
    assert!(
        stale_snapshot("Dockerfile", APT, stamped + 91 * day).is_some(),
        "91 days is not"
    );
    // written straight into the URI rather than through the ARG
    let inline = APT
        .replace("ARG DEBIAN_SNAPSHOT=20261120T000000Z\n", "")
        .replace("${DEBIAN_SNAPSHOT}", "20200101T000000Z");
    assert!(stale_snapshot("Dockerfile", &inline, now()).is_some());
    // a URI with no timestamp anywhere
    let none = APT
        .replace("ARG DEBIAN_SNAPSHOT=20261120T000000Z\n", "")
        .replace("${DEBIAN_SNAPSHOT}", "latest");
    assert!(stale_snapshot("Dockerfile", &none, now())
        .unwrap()
        .contains("no timestamp"));
    // a date that does not exist
    let nonsense = APT.replace("20261120T000000Z", "20261320T000000Z");
    assert!(stale_snapshot("Dockerfile", &nonsense, now()).is_some());
    // nothing to say for a file that pins no snapshot
    assert_eq!(stale_snapshot("Dockerfile", "FROM scratch\n", now()), None);
}

#[test]
fn it_catches_build_residue_left_in_the_layer() {
    assert!(residue_left(APT).is_empty());
    let bad = APT.replace(" /var/log/dpkg.log", "");
    assert_eq!(residue_left(&bad), vec!["/var/log/dpkg.log"]);
    assert!(
        residue_left("FROM scratch\n").is_empty(),
        "no apt, nothing to clear"
    );
}

#[test]
fn it_catches_bytecode_caches_and_the_project_in_the_dependency_layer() {
    let good = "ENV PYTHONDONTWRITEBYTECODE=1\n\
                RUN uv export --frozen --no-dev --no-emit-project -o r.txt && uv pip install --no-cache -r r.txt\n\
                RUN uv pip install --no-cache --no-deps .\n\
                # uv pip install . is not run here\n";
    assert!(bytecode_problems("D", good).is_empty());
    assert!(cached_installs(good).is_empty());
    assert!(project_install_problems("D", good).is_empty());

    let no_env = good.replace("ENV PYTHONDONTWRITEBYTECODE=1\n", "");
    assert_eq!(bytecode_problems("D", &no_env).len(), 1);
    let compiles = format!("{good}RUN python -m compileall /app\n");
    assert_eq!(bytecode_problems("D", &compiles).len(), 1);
    let cached = good.replace("install --no-cache --no-deps", "install --no-deps");
    assert_eq!(cached_installs(&cached).len(), 1);
    let project = good.replace("--no-deps .", ".");
    assert_eq!(project_install_problems("D", &project).len(), 1);
    let continued = good.replace("--no-deps .\n", "\\\n    . \\\n");
    assert!(project_install_problems("D", &continued).is_empty());
    let from_pyproject = good.replace(
        "uv export --frozen --no-dev --no-emit-project -o r.txt && ",
        "",
    );
    assert_eq!(project_install_problems("D", &from_pyproject).len(), 1);
}

#[test]
fn it_catches_a_lockfile_no_pull_request_audits() {
    let wf = vec![
        (
            "a.yml".to_string(),
            "on:\n  pull_request:\njobs: {x: {steps: [{run: cargo audit}]}}\n".to_string(),
        ),
        (
            "b.yml".to_string(),
            "on:\n  schedule:\njobs: {x: {steps: [{run: pip-audit}]}}\n".to_string(),
        ),
    ];
    assert_eq!(audited_on_pull_request(&wf, "cargo audit"), vec!["a.yml"]);
    assert!(audited_on_pull_request(&wf, "pip-audit").is_empty());
}

/// A repository with a workflow, a Dockerfile, a compose file and the two lockfiles.
fn tree() -> tempfile::TempDir {
    let t = tempfile::tempdir().unwrap();
    let w = |p: &str, s: &str| {
        let p: PathBuf = t.path().join(p);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, s).unwrap();
    };
    w(
        ".github/workflows/ci.yml",
        &format!("    - uses: a/b@{SHA} # v1\n"),
    );
    w("Dockerfile", &format!("FROM x/y:1@{DIGEST}\n"));
    w(
        "tests/docker-compose.test.yml",
        &format!("    image: x/y:1@{DIGEST}\n"),
    );
    w("relay/Cargo.toml", "[package]\n");
    w("relay/Cargo.lock", "");
    w("pyproject.toml", "");
    w("uv.lock", "");
    t
}

#[test]
fn it_reads_the_pinned_ecosystems_off_the_tree() {
    let t = tree();
    let found: Vec<&str> = ecosystems_with_pins(t.path()).into_keys().collect();
    assert_eq!(found, PINNED_ECOSYSTEMS);
    std::fs::remove_file(t.path().join("uv.lock")).unwrap();
    std::fs::write(
        t.path().join("tests/docker-compose.test.yml"),
        "services: {}\n",
    )
    .unwrap();
    let found: Vec<&str> = ecosystems_with_pins(t.path()).into_keys().collect();
    assert_eq!(found, ["cargo", "docker", "github-actions"]);
}

#[test]
fn it_catches_an_updater_reading_nothing() {
    let t = tree();
    let config: Value = serde_yaml_ng::from_str(
        "version: 2
updates:
  - package-ecosystem: cargo
    directory: /relay
  - package-ecosystem: cargo
    directories: [/relay, /moved]
  - package-ecosystem: docker
    directories: [/, /tests]
  - package-ecosystem: uv
  - package-ecosystem: npm
    directory: /
  - directory: /
  - package-ecosystem: docker-compose
    directories: ['/apps/*', /tests]
",
    )
    .unwrap();
    let updates = dependabot_updates(&config);
    let problems: Vec<Vec<String>> = updates
        .iter()
        .enumerate()
        .map(|(i, u)| updater_problems(t.path(), i, u))
        .collect();
    assert!(problems[0].is_empty(), "{:?}", problems[0]);
    assert_eq!(problems[1].len(), 1, "/moved does not exist");
    assert_eq!(problems[2].len(), 1, "/tests has no Dockerfile");
    assert!(problems[3].is_empty(), "uv reads pyproject.toml at /");
    assert!(
        problems[4][0].contains("ECOSYSTEM_MANIFESTS"),
        "npm is unknown"
    );
    assert!(problems[5][0].contains("no `package-ecosystem`"));
    assert!(
        problems[6].is_empty(),
        "a glob directory is Dependabot's to expand"
    );
    // a manifest that moved one level down leaves the directory there and reading nothing
    std::fs::rename(
        t.path().join("relay/Cargo.toml"),
        t.path().join("Cargo.toml"),
    )
    .unwrap();
    assert_eq!(updater_problems(t.path(), 0, updates[0]).len(), 1);
}
