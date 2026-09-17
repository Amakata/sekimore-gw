//! The clap command tree: every subcommand, its flags and their help keys.
//!
//! Split from the dispatch so that the shape of the CLI can be read in one place. Help text is
//! looked up at runtime from `relay/locales/*.json` via `crate::i18n::t`, so clap doc comments are
//! not used — they would be baked in at compile time.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::i18n::t;

/// Declares a subcommand group together with the endpoint each variant posts to.
///
/// The drift this exists to stop: a variant's name, its flags and its endpoint path used to live
/// in two files, so adding an endpoint meant editing both and nothing caught you when you edited
/// one. Here the path is written on the same line as the variant, and `path()` is generated from
/// that single place — the dispatch asks for it rather than repeating the literal.
///
/// `macro_rules!` rather than a proc-macro or a table of trait objects: clap's derive needs the
/// variants as real syntax, so every attribute (`long`, `default_value`, the runtime `help = t(..)`
/// lookup) stays written exactly as clap documents it, and `--help` is unchanged.
///
/// Two forms, because the root of the tree is not like its leaves:
///   `endpoints!`      every variant has an endpoint; `path()` returns `&'static str`.
///   `endpoints_root!` some variants only group others; `path()` returns `Option<&'static str>`
///                     and a grouping variant is written `Name(_)`.
macro_rules! endpoints {
    (
        $vis:vis enum $name:ident {
            $(
                $variant:ident ( $path:literal ) = $about:expr => {
                    $( $( #[$fmeta:meta] )* $field:ident : $ty:ty ),* $(,)?
                }
            ),* $(,)?
        }
    ) => {
        #[derive(Subcommand, Debug)]
        $vis enum $name {
            $(
                #[command(about = $about)]
                $variant { $( $( #[$fmeta] )* $field : $ty ),* },
            )*
        }

        impl $name {
            /// The relay endpoint this subcommand posts to.
            pub fn path(&self) -> &'static str {
                match self {
                    $( $name::$variant { .. } => $path, )*
                }
            }
        }
    };
}

macro_rules! endpoints_root {
    (
        $vis:vis enum $name:ident {
            $(
                $variant:ident ( $path:tt ) = $about:expr => {
                    $( $( #[$fmeta:meta] )* $field:ident : $ty:ty ),* $(,)?
                }
            ),* $(,)?
        }
    ) => {
        #[derive(Subcommand, Debug)]
        $vis enum $name {
            $(
                #[command(about = $about)]
                $variant { $( $( #[$fmeta] )* $field : $ty ),* },
            )*
        }

        impl $name {
            /// The endpoint this subcommand posts to, or `None` when it only groups others.
            pub fn path(&self) -> Option<&'static str> {
                match self {
                    $( $name::$variant { .. } => endpoints_root!(@path $path), )*
                }
            }
        }
    };
    (@path _) => { None };
    (@path $p:literal) => { Some($p) };
}

endpoints_root! {
    pub enum AgentCmd {
        Whoami("/whoami") = t("agent.whoami") => {},
        Guide(_) = t("agent.guide") => {
            #[arg(long, help = t("agent.guide.lang"))]
            lang: Option<String>,
        },
        Pr(_) = t("agent.pr") => {
            #[command(subcommand)]
            cmd: PrCmd,
        },
        Issue(_) = t("agent.issue") => {
            #[command(subcommand)]
            cmd: IssueCmd,
        },
        Ci(_) = t("agent.ci") => {
            #[command(subcommand)]
            cmd: CiCmd,
        },
        Project(_) = t("agent.project") => {
            #[command(subcommand)]
            cmd: ProjectCmd,
        },
        Release(_) = t("agent.release") => {
            #[command(subcommand)]
            cmd: ReleaseCmd,
        },
        Repo(_) = t("agent.repo") => {
            #[command(subcommand)]
            cmd: RepoCmd,
        },
        Search("/search/issues") = t("agent.search") => {
            #[arg(help = t("agent.search.query"))]
            query: String,
            #[arg(long, default_value_t = 20, help = t("agent.search.limit"))]
            limit: u32,
            #[arg(long, help = t("agent.search.json"))]
            json: bool,
        },
    }
}

#[derive(Args, Debug, Default)]
pub struct Number {
    #[arg(long, help = t("agent.number"))]
    pub number: u64,
}

endpoints! {
    pub enum PrCmd {
        Create("/pr/create") = t("agent.pr.create") => {
            #[arg(long, help = t("agent.pr.create.head"))]
            head: String,
            #[arg(long, help = t("agent.pr.create.base"))]
            base: String,
            #[arg(long, help = t("agent.pr.create.title"))]
            title: String,
            #[arg(long, default_value = "", help = t("agent.pr.create.body"))]
            body: String,
        },
        Comment("/pr/comment") = t("agent.pr.comment") => {
            #[arg(long, help = t("agent.number"))]
            number: u64,
            #[arg(long, help = t("agent.body"))]
            body: String,
        },
        Review("/pr/review") = t("agent.pr.review") => {
            #[arg(long, help = t("agent.number"))]
            number: u64,
            #[arg(long, default_value = "COMMENT", help = t("agent.pr.review.event"))]
            event: String,
            #[arg(long, default_value = "", help = t("agent.body"))]
            body: String,
        },
        Merge("/pr/merge") = t("agent.pr.merge") => {
            #[arg(long, help = t("agent.number"))]
            number: u64,
            #[arg(long, help = t("agent.pr.merge.method"))]
            method: Option<String>,
            #[arg(long, help = t("agent.pr.merge.title"))]
            title: Option<String>,
            #[arg(long, help = t("agent.pr.merge.message"))]
            message: Option<String>,
            #[arg(long, help = t("agent.pr.merge.delete_branch"))]
            delete_branch: bool,
        },
        Close("/pr/close") = t("agent.pr.close") => {
            #[arg(long, help = t("agent.number"))]
            number: u64,
        },
        Reopen("/pr/reopen") = t("agent.pr.reopen") => {
            #[arg(long, help = t("agent.number"))]
            number: u64,
        },
        Update("/pr/update") = t("agent.pr.update") => {
            #[arg(long, help = t("agent.number"))]
            number: u64,
            #[arg(long, help = t("agent.pr.update.title"))]
            title: Option<String>,
            #[arg(long, help = t("agent.pr.update.body"))]
            body: Option<String>,
            #[arg(long, help = t("agent.pr.update.base"))]
            base: Option<String>,
        },
        RequestReview("/pr/request-review") = t("agent.pr.request_review") => {
            #[arg(long, help = t("agent.number"))]
            number: u64,
            #[arg(long, help = t("agent.pr.reviewers"))]
            reviewers: Option<String>,
            #[arg(long, help = t("agent.pr.team_reviewers"))]
            teams: Option<String>,
        },
        Status("/pr/status") = t("agent.pr.status") => {
            #[arg(long, help = t("agent.number"))]
            number: u64,
            #[arg(long, help = t("agent.pr.status.json"))]
            json: bool,
        },
        View("/pr/view") = t("agent.pr.view") => {
            #[arg(long, help = t("agent.number"))]
            number: u64,
            #[arg(long, help = t("agent.json"))]
            json: bool,
        },
        Comments("/pr/comments") = t("agent.pr.comments") => {
            #[arg(long, help = t("agent.number"))]
            number: u64,
            #[arg(long, default_value_t = 30, help = t("agent.comments.limit"))]
            limit: u32,
            #[arg(long, help = t("agent.json"))]
            json: bool,
        },
        List("/pr/list") = t("agent.pr.list") => {
            #[arg(long, default_value = "open", help = t("agent.list.state"))]
            state: String,
            #[arg(long, help = t("agent.pr.list.base"))]
            base: Option<String>,
            #[arg(long, default_value_t = 20, help = t("agent.list.limit"))]
            limit: u32,
            #[arg(long, help = t("agent.json"))]
            json: bool,
        },
    }
}

endpoints! {
    pub enum CiCmd {
        Runs("/ci/runs") = t("agent.ci.runs") => {
            #[arg(long = "ref", help = t("agent.ci.runs.ref"))]
            git_ref: String,
        },
        Jobs("/ci/jobs") = t("agent.ci.jobs") => {
            #[arg(long, help = t("agent.number"))]
            number: Option<u64>,
            #[arg(long, help = t("agent.ci.run_id"))]
            run_id: Option<u64>,
        },
        Rerun("/ci/rerun") = t("agent.ci.rerun") => {
            #[arg(long, help = t("agent.ci.run_id"))]
            run_id: u64,
            #[arg(long, help = t("agent.ci.rerun.all"))]
            all: bool,
        },
        Cancel("/ci/cancel") = t("agent.ci.cancel") => {
            #[arg(long, help = t("agent.ci.run_id"))]
            run_id: u64,
        },
        Log("/ci/log") = t("agent.ci.log") => {
            #[arg(long, help = t("agent.ci.log.number"))]
            number: Option<u64>,
            #[arg(long, help = t("agent.ci.log.run_id"))]
            run_id: Option<u64>,
            #[arg(long, help = t("agent.ci.log.job_id"))]
            job_id: Option<u64>,
            #[arg(long, default_value = "200", help = t("agent.ci.log.window"))]
            window: u64,
            #[arg(long, help = t("agent.ci.log.before"))]
            before: Option<u64>,
            #[arg(long, help = t("agent.ci.log.json"))]
            json: bool,
        },
    }
}

endpoints! {
    pub enum IssueCmd {
        Create("/issue/create") = t("agent.issue.create") => {
            #[arg(long, help = t("agent.issue.title"))]
            title: String,
            #[arg(long, default_value = "", help = t("agent.body"))]
            body: String,
            #[arg(long, help = t("agent.issue.labels"))]
            labels: Option<String>,
        },
        Comment("/issue/comment") = t("agent.issue.comment") => {
            #[arg(long, help = t("agent.number"))]
            number: u64,
            #[arg(long, help = t("agent.body"))]
            body: String,
        },
        Close("/issue/close") = t("agent.issue.close") => {
            #[arg(long, help = t("agent.number"))]
            number: u64,
        },
        Reopen("/issue/reopen") = t("agent.issue.reopen") => {
            #[arg(long, help = t("agent.number"))]
            number: u64,
        },
        Label("/issue/label") = t("agent.issue.label") => {
            #[arg(long, help = t("agent.number"))]
            number: u64,
            #[arg(long, help = t("agent.issue.labels"))]
            labels: String,
        },
        Unlabel("/issue/unlabel") = t("agent.issue.unlabel") => {
            #[arg(long, help = t("agent.number"))]
            number: u64,
            #[arg(long, help = t("agent.issue.unlabel.labels"))]
            labels: String,
        },
        Assign("/issue/assign") = t("agent.issue.assign") => {
            #[arg(long, help = t("agent.number"))]
            number: u64,
            #[arg(long, help = t("agent.issue.assignees"))]
            assignees: String,
        },
        Unassign("/issue/unassign") = t("agent.issue.unassign") => {
            #[arg(long, help = t("agent.number"))]
            number: u64,
            #[arg(long, help = t("agent.issue.unassign.assignees"))]
            assignees: String,
        },
        View("/issue/view") = t("agent.issue.view") => {
            #[arg(long, help = t("agent.number"))]
            number: u64,
            #[arg(long, help = t("agent.json"))]
            json: bool,
        },
        Comments("/issue/comments") = t("agent.issue.comments") => {
            #[arg(long, help = t("agent.number"))]
            number: u64,
            #[arg(long, default_value_t = 30, help = t("agent.comments.limit"))]
            limit: u32,
            #[arg(long, help = t("agent.json"))]
            json: bool,
        },
        List("/issue/list") = t("agent.issue.list") => {
            #[arg(long, default_value = "open", help = t("agent.list.state"))]
            state: String,
            #[arg(long, help = t("agent.issue.list.labels"))]
            labels: Option<String>,
            #[arg(long, help = t("agent.issue.list.assignee"))]
            assignee: Option<String>,
            #[arg(long, default_value_t = 20, help = t("agent.list.limit"))]
            limit: u32,
            #[arg(long, help = t("agent.json"))]
            json: bool,
        },
    }
}

endpoints! {
    pub enum ReleaseCmd {
        Create("/release/create") = t("agent.release.create") => {
            #[arg(long, help = t("agent.release.tag"))]
            tag: String,
            #[arg(long, help = t("agent.release.title"))]
            title: Option<String>,
            #[arg(long, help = t("agent.release.notes"))]
            notes: Option<String>,
            #[arg(long, help = t("agent.release.notes_file"))]
            notes_file: Option<PathBuf>,
            #[arg(long, help = t("agent.release.generate_notes"))]
            generate_notes: bool,
            #[arg(long, help = t("agent.release.draft"))]
            draft: bool,
            #[arg(long, help = t("agent.release.prerelease"))]
            prerelease: bool,
        },
        Edit("/release/edit") = t("agent.release.edit") => {
            #[arg(long, help = t("agent.release.tag"))]
            tag: String,
            #[arg(long, help = t("agent.release.title"))]
            title: Option<String>,
            #[arg(long, help = t("agent.release.notes"))]
            notes: Option<String>,
            #[arg(long, help = t("agent.release.notes_file"))]
            notes_file: Option<PathBuf>,
            #[arg(long, help = t("agent.release.edit.draft"))]
            draft: Option<bool>,
            #[arg(long, help = t("agent.release.edit.prerelease"))]
            prerelease: Option<bool>,
        },
        View("/release/view") = t("agent.release.view") => {
            #[arg(long, help = t("agent.release.tag"))]
            tag: String,
        },
        List("/release/list") = t("agent.release.list") => {
            #[arg(long, default_value_t = 20, help = t("agent.release.limit"))]
            limit: u32,
        },
    }
}

endpoints! {
    pub enum RepoCmd {
        Vocabulary("/repo/vocabulary") = t("agent.repo.vocabulary") => {},
    }
}

endpoints! {
    pub enum ProjectCmd {
        AddItem("/project/add-item") = t("agent.project.add_item") => {
            #[arg(long, help = t("agent.project.project_id"))]
            project_id: String,
            #[arg(long, help = t("agent.project.content_id"))]
            content_id: String,
        },
        UpdateItem("/project/update-item") = t("agent.project.update_item") => {
            #[arg(long, help = t("agent.project.project_id"))]
            project_id: String,
            #[arg(long, help = t("agent.project.item_id"))]
            item_id: String,
            #[arg(long, help = t("agent.project.field_id"))]
            field_id: String,
            #[arg(long, help = t("agent.project.update_item.value"))]
            value: String,
        },
        List("/project/list") = t("agent.project.list") => {
            #[arg(long, help = t("agent.project.project_id"))]
            project_id: String,
            #[arg(long, default_value_t = 20)]
            first: u32,
        },
        Fields("/project/fields") = t("agent.project.fields") => {
            #[arg(long, help = t("agent.project.project_id"))]
            project_id: String,
            #[arg(long, default_value_t = 50)]
            first: u32,
        },
    }
}
