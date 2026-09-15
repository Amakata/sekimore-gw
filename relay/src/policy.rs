//! 案件ポリシー。
//!
//! ここが Rust で書く一番の理由。
//!
//! Go 版では `FindRepo` の戻り値を無視して上流を叩くコードが書けてしまう。
//! 検査漏れが型で防げないので、レビューとテストで担保するしかない。
//! この構成では **権限制御の全責任が関所にある**ので、それは弱い。
//!
//! Rust では「検査済み」を型にできる:
//!   - 上流を叩く関数は `Authorized<'_>`（API）/ `GitAuthorized<'_>`（git）しか受け取らない
//!   - これらはポリシー検査を通した時だけ作られる
//!   - つまり **検査を忘れるとコンパイルが通らない**

use std::collections::HashSet;
use std::fmt;

// ---- リソース × アクション ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resource {
    Pr,
    Issue,
    Project,
    Repo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    Create,
    Comment,
    Review,
    Merge,
    Close,
    Label,
    Assign,
    Read,
    AddItem,
    UpdateItem,
}

impl Resource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Resource::Pr => "pr",
            Resource::Issue => "issue",
            Resource::Project => "project",
            Resource::Repo => "repo",
        }
    }
    /// そのリソースに存在するアクション。設定の typo を弾く。
    pub fn valid_actions(&self) -> &'static [Action] {
        use Action::*;
        match self {
            Resource::Pr => &[Create, Comment, Review, Merge, Close, Read],
            Resource::Issue => &[Create, Comment, Close, Label, Assign],
            Resource::Project => &[Read, AddItem, UpdateItem],
            Resource::Repo => &[Read],
        }
    }
    pub const ALL: [Resource; 4] = [
        Resource::Pr,
        Resource::Issue,
        Resource::Project,
        Resource::Repo,
    ];
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Create => "create",
            Action::Comment => "comment",
            Action::Review => "review",
            Action::Merge => "merge",
            Action::Close => "close",
            Action::Label => "label",
            Action::Assign => "assign",
            Action::Read => "read",
            Action::AddItem => "add_item",
            Action::UpdateItem => "update_item",
        }
    }
}

/// "pr:create" 形式のパース。Go 版では文字列キーだったので
/// "pr:delete" のような存在しない組み合わせも黙って通った。
pub fn parse_permission(s: &str) -> Result<(Resource, Action), String> {
    let (r, a) = s
        .split_once(':')
        .ok_or_else(|| format!("{s:?}: must be resource:action"))?;
    let resource = match r.trim() {
        "pr" => Resource::Pr,
        "issue" => Resource::Issue,
        "project" => Resource::Project,
        "repo" => Resource::Repo,
        other => {
            return Err(format!(
                "unknown resource {other:?} (known: issue, pr, project, repo)"
            ))
        }
    };
    let action = match a.trim() {
        "create" => Action::Create,
        "comment" => Action::Comment,
        "review" => Action::Review,
        "merge" => Action::Merge,
        "close" => Action::Close,
        "label" => Action::Label,
        "assign" => Action::Assign,
        "read" => Action::Read,
        "add_item" => Action::AddItem,
        "update_item" => Action::UpdateItem,
        other => return Err(format!("unknown action {other:?}")),
    };
    if !resource.valid_actions().contains(&action) {
        return Err(format!(
            "{}:{} is not a valid combination",
            resource.as_str(),
            action.as_str()
        ));
    }
    Ok((resource, action))
}

/// 一覧表示用: 全ての有効な "resource:action"。
pub fn all_permission_keys() -> Vec<String> {
    let mut v = Vec::new();
    for r in Resource::ALL {
        for a in r.valid_actions() {
            v.push(format!("{}:{}", r.as_str(), a.as_str()));
        }
    }
    v.sort();
    v
}

// ---- git の動詞 ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GitVerb {
    UploadPack,
    ReceivePack,
}

impl GitVerb {
    pub fn as_str(&self) -> &'static str {
        match self {
            GitVerb::UploadPack => "git-upload-pack",
            GitVerb::ReceivePack => "git-receive-pack",
        }
    }
    /// `git <subcommand>` 形式（テスト用ローカル上流で使う）。
    pub fn as_subcommand(&self) -> &'static str {
        match self {
            GitVerb::UploadPack => "upload-pack",
            GitVerb::ReceivePack => "receive-pack",
        }
    }
    pub fn is_write(&self) -> bool {
        matches!(self, GitVerb::ReceivePack)
    }
}

// ---- リポジトリと案件 ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    ReadOnly,
    ReadWrite,
}

impl Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::ReadOnly => "read-only",
            Mode::ReadWrite => "read-write",
        }
    }
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim() {
            "read-only" => Ok(Mode::ReadOnly),
            "read-write" => Ok(Mode::ReadWrite),
            other => Err(format!("unknown mode {other:?} (read-only | read-write)")),
        }
    }
}

/// 直接 push を既定で許すブランチ glob。エージェントの名前空間。
pub const DEFAULT_PUSH_GLOBS: &[&str] = &["sekimore/*"];

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RepoPolicy {
    pub full_name: String,
    pub mode: Mode,
    /// PR の base として許可するブランチ。空 = 全て
    pub bases: Vec<String>,
    /// 直接 push を許可するブランチ glob（`refs/heads/` を除いた名前に対して）
    pub push: Vec<String>,
}

impl RepoPolicy {
    pub fn new(full_name: &str, mode: Mode) -> Self {
        RepoPolicy {
            full_name: full_name.to_string(),
            mode,
            bases: Vec::new(),
            push: DEFAULT_PUSH_GLOBS.iter().map(|s| s.to_string()).collect(),
        }
    }
    pub fn allows_base(&self, branch: &str) -> bool {
        self.bases.is_empty() || self.bases.iter().any(|b| b == branch)
    }
    /// `refs/heads/<branch>` への直接 push を許すか。
    pub fn allows_push(&self, branch: &str) -> bool {
        self.push.iter().any(|g| glob_match(g, branch))
    }
    pub fn can_write(&self) -> bool {
        self.mode == Mode::ReadWrite
    }
}

/// 最小 glob: `*` は任意の列（`/` を含む）、`?` は 1 文字。それ以外は完全一致。
pub fn glob_match(pattern: &str, text: &str) -> bool {
    fn rec(p: &[u8], t: &[u8]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (Some(b'*'), _) => rec(&p[1..], t) || (!t.is_empty() && rec(p, &t[1..])),
            (Some(b'?'), Some(_)) => rec(&p[1..], &t[1..]),
            (Some(a), Some(b)) if a == b => rec(&p[1..], &t[1..]),
            _ => false,
        }
    }
    rec(pattern.as_bytes(), text.as_bytes())
}

/// 隔離単位 = 案件。
#[derive(Debug, Clone)]
pub struct Project {
    pub name: String,
    pub repos: Vec<RepoPolicy>,
    perms: HashSet<(Resource, Action)>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Denied {
    /// 案件に含まれないリポジトリ
    RepoNotInProject { repo: String, project: String },
    /// read-only リポジトリへの書き込み
    RepoReadOnly { repo: String, project: String },
    /// 許可されていない base ブランチ
    BaseNotAllowed { branch: String },
    /// ポリシーで許可されていない操作 (既定拒否)
    NotPermitted {
        resource: &'static str,
        action: &'static str,
    },
    /// git-upload-pack / git-receive-pack 以外
    UnsupportedCommand { cmdline: String },
    /// 名前空間やブランチ制限で拒否された ref
    RefNotAllowed { name: String, reason: &'static str },
    /// 削除は既定拒否
    DeleteNotAllowed { name: String },
    /// ref 名として不正
    InvalidRef { name: String, reason: &'static str },
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Denied::RepoNotInProject { repo, project } => {
                write!(f, "repository {repo:?} is not in project {project:?}")
            }
            Denied::RepoReadOnly { repo, project } => {
                write!(f, "{repo} is read-only in project {project}")
            }
            Denied::BaseNotAllowed { branch } => write!(f, "base branch {branch} is not allowed"),
            Denied::NotPermitted { resource, action } => {
                write!(f, "{resource}:{action} is not allowed by policy")
            }
            Denied::UnsupportedCommand { cmdline } => write!(f, "unsupported command: {cmdline}"),
            Denied::RefNotAllowed { name, reason } => {
                write!(f, "push to {name} is not allowed: {reason}")
            }
            Denied::DeleteNotAllowed { name } => {
                write!(
                    f,
                    "deleting {name} is not allowed (relay.allow_delete is false)"
                )
            }
            Denied::InvalidRef { name, reason } => write!(f, "invalid ref {name:?}: {reason}"),
        }
    }
}

impl std::error::Error for Denied {}

impl Denied {
    /// 監査ログ用の短い種別。
    pub fn kind(&self) -> &'static str {
        match self {
            Denied::RepoNotInProject { .. } => "repo_not_in_project",
            Denied::RepoReadOnly { .. } => "repo_read_only",
            Denied::BaseNotAllowed { .. } => "base_not_allowed",
            Denied::NotPermitted { .. } => "not_permitted",
            Denied::UnsupportedCommand { .. } => "unsupported_command",
            Denied::RefNotAllowed { .. } => "ref_not_allowed",
            Denied::DeleteNotAllowed { .. } => "delete_not_allowed",
            Denied::InvalidRef { .. } => "invalid_ref",
        }
    }
}

/// **API 操作の検査を通した証明書**。
///
/// このライフタイム付きの型は `Project::authorize` からしか作れない。
/// 上流 API を叩く関数はこれを要求するので、検査漏れがコンパイルエラーになる。
#[derive(Debug, PartialEq)]
pub struct Authorized<'p> {
    repo: &'p RepoPolicy,
    resource: Resource,
    action: Action,
    project: &'p str,
}

impl<'p> Authorized<'p> {
    pub fn repo(&self) -> &'p str {
        &self.repo.full_name
    }
    pub fn project(&self) -> &'p str {
        self.project
    }
    pub fn policy(&self) -> &'p RepoPolicy {
        self.repo
    }
    /// 監査ログ用。何が許可されたかを記録できる。
    pub fn permission(&self) -> (&'static str, &'static str) {
        (self.resource.as_str(), self.action.as_str())
    }
    /// 上流呼び出し側が「正しい種類の証明」を受け取ったことを確認する。
    /// （`pr:create` の証明で `pr:merge` を叩くようなプログラミングミスを実行時に止める）
    pub fn ensure(&self, resource: Resource, action: Action) -> Result<(), Denied> {
        if self.resource == resource && self.action == action {
            Ok(())
        } else {
            Err(Denied::NotPermitted {
                resource: resource.as_str(),
                action: action.as_str(),
            })
        }
    }
}

/// **git 経路の検査を通した証明書**。`Project::authorize_git` からしか作れない。
#[derive(Debug, PartialEq)]
pub struct GitAuthorized<'p> {
    repo: &'p RepoPolicy,
    verb: GitVerb,
    project: &'p str,
}

impl<'p> GitAuthorized<'p> {
    pub fn repo(&self) -> &'p str {
        &self.repo.full_name
    }
    pub fn project(&self) -> &'p str {
        self.project
    }
    pub fn verb(&self) -> GitVerb {
        self.verb
    }
    pub fn policy(&self) -> &'p RepoPolicy {
        self.repo
    }
}

impl Project {
    pub fn new(name: impl Into<String>) -> Self {
        Project {
            name: name.into(),
            repos: Vec::new(),
            perms: HashSet::new(),
        }
    }

    /// 設定から組み立てる。権限名の typo はここで弾く。
    pub fn try_new(
        name: impl Into<String>,
        repos: Vec<RepoPolicy>,
        permissions: &[String],
    ) -> Result<Self, String> {
        let mut p = Project::new(name);
        for r in &repos {
            if r.full_name.split('/').filter(|s| !s.is_empty()).count() != 2 {
                return Err(format!("repo {:?} must be Org/Repo", r.full_name));
            }
            if repos
                .iter()
                .filter(|o| o.full_name.eq_ignore_ascii_case(&r.full_name))
                .count()
                > 1
            {
                return Err(format!("repo {:?} is listed more than once", r.full_name));
            }
        }
        p.repos = repos;
        for spec in permissions {
            let (r, a) = parse_permission(spec)?;
            p.perms.insert((r, a));
        }
        Ok(p)
    }

    pub fn with_repo(mut self, full_name: &str, mode: Mode, bases: &[&str]) -> Self {
        let mut rp = RepoPolicy::new(full_name, mode);
        rp.bases = bases.iter().map(|s| s.to_string()).collect();
        self.repos.push(rp);
        self
    }

    pub fn grant(mut self, spec: &str) -> Self {
        let (r, a) = parse_permission(spec).expect("invalid permission spec");
        self.perms.insert((r, a));
        self
    }

    pub fn is_granted(&self, resource: Resource, action: Action) -> bool {
        self.perms.contains(&(resource, action))
    }

    /// 案件に含まれるリポジトリを探す。含まれなければ拒否 = 案件外への到達を拒否する唯一の防壁。
    pub fn find_repo(&self, path: &str) -> Result<&RepoPolicy, Denied> {
        let want = path.trim_start_matches('/').trim_end_matches(".git");
        self.repos
            .iter()
            .find(|r| r.full_name.eq_ignore_ascii_case(want))
            .ok_or_else(|| Denied::RepoNotInProject {
                repo: want.to_string(),
                project: self.name.clone(),
            })
    }

    /// API 操作の唯一の入口。ここを通らないと `Authorized` は存在しない。
    ///
    /// 書き込み系アクションなら read-only 判定も自動で行う。
    pub fn authorize(
        &self,
        repo: &str,
        resource: Resource,
        action: Action,
    ) -> Result<Authorized<'_>, Denied> {
        // 1. 既定拒否（案件外リポジトリでも、まず「許可されていない操作」として落ちる = 情報を漏らさない）
        if !self.perms.contains(&(resource, action)) {
            return Err(Denied::NotPermitted {
                resource: resource.as_str(),
                action: action.as_str(),
            });
        }
        // 2. 案件に含まれるリポジトリか
        let found = self.find_repo(repo)?;
        // 3. 書き込み系なら read-write が必要
        if is_write(action) && found.mode == Mode::ReadOnly {
            return Err(Denied::RepoReadOnly {
                repo: found.full_name.clone(),
                project: self.name.clone(),
            });
        }
        Ok(Authorized {
            repo: found,
            resource,
            action,
            project: &self.name,
        })
    }

    /// PR 作成のように base ブランチの検査も要る場合。
    pub fn authorize_pr(&self, repo: &str, base: &str) -> Result<Authorized<'_>, Denied> {
        let auth = self.authorize(repo, Resource::Pr, Action::Create)?;
        if !auth.repo.allows_base(base) {
            return Err(Denied::BaseNotAllowed {
                branch: base.to_string(),
            });
        }
        Ok(auth)
    }

    /// git 経路の唯一の入口。receive-pack は read-write を要求する。
    pub fn authorize_git(
        &self,
        verb: GitVerb,
        repo_path: &str,
    ) -> Result<GitAuthorized<'_>, Denied> {
        let found = self.find_repo(repo_path)?;
        if verb.is_write() && !found.can_write() {
            return Err(Denied::RepoReadOnly {
                repo: found.full_name.clone(),
                project: self.name.clone(),
            });
        }
        Ok(GitAuthorized {
            repo: found,
            verb,
            project: &self.name,
        })
    }

    pub fn granted(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .perms
            .iter()
            .map(|(r, a)| format!("{}:{}", r.as_str(), a.as_str()))
            .collect();
        v.sort();
        v
    }
}

fn is_write(action: Action) -> bool {
    !matches!(action, Action::Read)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case_a() -> Project {
        Project::new("case-a")
            .with_repo("LibOrg/awesome-lib", Mode::ReadWrite, &["main"])
            .with_repo("VendorOrg/reference-impl", Mode::ReadOnly, &[])
            .grant("pr:create")
            .grant("issue:create")
            .grant("project:read")
    }

    #[test]
    fn authorized_path_carries_repo_and_project() {
        let p = case_a();
        let auth = p.authorize_pr("LibOrg/awesome-lib", "main").unwrap();
        assert_eq!(auth.repo(), "LibOrg/awesome-lib");
        assert_eq!(auth.project(), "case-a");
        assert_eq!(auth.permission(), ("pr", "create"));
        assert!(auth.ensure(Resource::Pr, Action::Create).is_ok());
        assert!(auth.ensure(Resource::Pr, Action::Merge).is_err());
    }

    #[test]
    fn out_of_project_repo_is_denied() {
        let p = case_a();
        assert_eq!(
            p.authorize("Attacker/evil", Resource::Issue, Action::Create),
            Err(Denied::RepoNotInProject {
                repo: "Attacker/evil".into(),
                project: "case-a".into()
            })
        );
        // 同じ ORG の別リポジトリも拒否
        assert!(p
            .authorize("LibOrg/other", Resource::Issue, Action::Create)
            .is_err());
    }

    #[test]
    fn find_repo_same_org_other_repo_denied() {
        let p = case_a();
        assert!(p.find_repo("LibOrg/other-lib").is_err());
        assert!(p.find_repo("Attacker/evil-repo").is_err());
        assert!(p.find_repo("liborg/AWESOME-LIB.git").is_ok());
    }

    #[test]
    fn repo_suffix_and_slash_are_normalized() {
        let p = case_a();
        for input in [
            "LibOrg/awesome-lib",
            "LibOrg/awesome-lib.git",
            "/LibOrg/awesome-lib.git",
        ] {
            assert!(
                p.authorize(input, Resource::Pr, Action::Create).is_ok(),
                "{input}"
            );
        }
    }

    #[test]
    fn read_only_repo_blocks_writes_but_allows_reads() {
        let p = case_a();
        assert_eq!(
            p.authorize("VendorOrg/reference-impl", Resource::Pr, Action::Create),
            Err(Denied::RepoReadOnly {
                repo: "VendorOrg/reference-impl".into(),
                project: "case-a".into()
            })
        );
        // read は通る (project:read を許可しているので)
        assert!(p
            .authorize("VendorOrg/reference-impl", Resource::Project, Action::Read)
            .is_ok());
    }

    #[test]
    fn default_deny() {
        let p = case_a();
        // pr:comment は許可していない
        assert_eq!(
            p.authorize("LibOrg/awesome-lib", Resource::Pr, Action::Comment),
            Err(Denied::NotPermitted {
                resource: "pr",
                action: "comment"
            })
        );
        // 順序も重要: 権限判定が先なので、案件外リポジトリでも
        // まず「許可されていない操作」として落ちる (情報を漏らさない)
        assert_eq!(
            p.authorize("Attacker/evil", Resource::Pr, Action::Merge),
            Err(Denied::NotPermitted {
                resource: "pr",
                action: "merge"
            })
        );
    }

    #[test]
    fn disallowed_base_is_denied() {
        let p = case_a();
        assert_eq!(
            p.authorize_pr("LibOrg/awesome-lib", "production"),
            Err(Denied::BaseNotAllowed {
                branch: "production".into()
            })
        );
    }

    #[test]
    fn allows_base_empty_means_all() {
        let mut r = RepoPolicy::new("Org/Repo", Mode::ReadWrite);
        assert!(r.allows_base("anything"));
        r.bases = vec!["main".into(), "develop".into()];
        assert!(r.allows_base("main"));
        assert!(!r.allows_base("production"));
    }

    #[test]
    fn push_glob_default_sekimore_namespace() {
        let r = RepoPolicy::new("Org/Repo", Mode::ReadWrite);
        assert!(r.allows_push("sekimore/main-abc1234"));
        assert!(r.allows_push("sekimore/release/v1-abc1234"));
        assert!(!r.allows_push("main"));
        assert!(!r.allows_push("sekimore"));
        assert!(!r.allows_push("feature/sekimore/x"));
        assert!(glob_match("release/*", "release/v1"));
        assert!(glob_match("v?", "v1"));
        assert!(!glob_match("v?", "v10"));
        assert!(glob_match("main", "main"));
    }

    #[test]
    fn authorize_git_receive_pack_requires_read_write() {
        let p = case_a();
        let a = p
            .authorize_git(GitVerb::UploadPack, "VendorOrg/reference-impl.git")
            .unwrap();
        assert_eq!(a.repo(), "VendorOrg/reference-impl");
        assert_eq!(a.verb(), GitVerb::UploadPack);
        assert!(matches!(
            p.authorize_git(GitVerb::ReceivePack, "VendorOrg/reference-impl.git"),
            Err(Denied::RepoReadOnly { .. })
        ));
        assert!(matches!(
            p.authorize_git(GitVerb::UploadPack, "Attacker/evil.git"),
            Err(Denied::RepoNotInProject { .. })
        ));
        assert!(p
            .authorize_git(GitVerb::ReceivePack, "/LibOrg/awesome-lib.git")
            .is_ok());
    }

    #[test]
    fn invalid_permission_specs_are_rejected() {
        assert!(parse_permission("pr:create").is_ok());
        // Go 版では文字列キーだったので通ってしまった組み合わせ
        assert!(parse_permission("pr:delete").is_err());
        assert!(parse_permission("workflow:run").is_err());
        assert!(parse_permission("repo:merge").is_err()); // 存在しない組み合わせ
        assert!(parse_permission("prcreate").is_err());
        assert!(Project::try_new("x", vec![], &["pr:delete".to_string()]).is_err());
        assert!(Project::try_new("x", vec![RepoPolicy::new("nope", Mode::ReadOnly)], &[]).is_err());
        assert_eq!(all_permission_keys().len(), 15); // pr:read 追加 (0.1.3)
    }
}
