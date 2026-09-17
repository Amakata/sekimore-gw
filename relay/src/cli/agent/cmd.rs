//! The clap command tree: every subcommand, its flags and their help keys.
//!
//! Split from the dispatch so that the shape of the CLI can be read in one place. Help text is
//! looked up at runtime from `relay/locales/*.json` via `crate::i18n::t`, so clap doc comments are
//! not used — they would be baked in at compile time.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::i18n::t;

#[derive(Subcommand, Debug)]
pub enum AgentCmd {
    #[command(about = t("agent.whoami"))]
    Whoami,
    #[command(about = t("agent.guide"))]
    Guide {
        #[arg(long, help = t("agent.guide.lang"))]
        lang: Option<String>,
    },
    #[command(about = t("agent.pr"))]
    Pr {
        #[command(subcommand)]
        cmd: PrCmd,
    },
    #[command(about = t("agent.issue"))]
    Issue {
        #[command(subcommand)]
        cmd: IssueCmd,
    },
    #[command(about = t("agent.ci"))]
    Ci {
        #[command(subcommand)]
        cmd: CiCmd,
    },
    #[command(about = t("agent.project"))]
    Project {
        #[command(subcommand)]
        cmd: ProjectCmd,
    },
    #[command(about = t("agent.release"))]
    Release {
        #[command(subcommand)]
        cmd: ReleaseCmd,
    },
    #[command(about = t("agent.repo"))]
    Repo {
        #[command(subcommand)]
        cmd: RepoCmd,
    },
    #[command(about = t("agent.search"))]
    Search {
        #[arg(help = t("agent.search.query"))]
        query: String,
        #[arg(long, default_value_t = 20, help = t("agent.search.limit"))]
        limit: u32,
        #[arg(long, help = t("agent.search.json"))]
        json: bool,
    },
}

#[derive(Args, Debug, Default)]
pub struct Number {
    #[arg(long, help = t("agent.number"))]
    pub number: u64,
}

#[derive(Subcommand, Debug)]
pub enum PrCmd {
    #[command(about = t("agent.pr.create"))]
    Create {
        #[arg(long, help = t("agent.pr.create.head"))]
        head: String,
        #[arg(long, help = t("agent.pr.create.base"))]
        base: String,
        #[arg(long, help = t("agent.pr.create.title"))]
        title: String,
        #[arg(long, default_value = "", help = t("agent.pr.create.body"))]
        body: String,
    },
    #[command(about = t("agent.pr.comment"))]
    Comment {
        #[arg(long, help = t("agent.number"))]
        number: u64,
        #[arg(long, help = t("agent.body"))]
        body: String,
    },
    #[command(about = t("agent.pr.review"))]
    Review {
        #[arg(long, help = t("agent.number"))]
        number: u64,
        #[arg(long, default_value = "COMMENT", help = t("agent.pr.review.event"))]
        event: String,
        #[arg(long, default_value = "", help = t("agent.body"))]
        body: String,
    },
    #[command(about = t("agent.pr.merge"))]
    Merge {
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
    #[command(about = t("agent.pr.close"))]
    Close {
        #[arg(long, help = t("agent.number"))]
        number: u64,
    },
    #[command(about = t("agent.pr.reopen"))]
    Reopen {
        #[arg(long, help = t("agent.number"))]
        number: u64,
    },
    #[command(about = t("agent.pr.update"))]
    Update {
        #[arg(long, help = t("agent.number"))]
        number: u64,
        #[arg(long, help = t("agent.pr.update.title"))]
        title: Option<String>,
        #[arg(long, help = t("agent.pr.update.body"))]
        body: Option<String>,
        #[arg(long, help = t("agent.pr.update.base"))]
        base: Option<String>,
    },
    #[command(about = t("agent.pr.request_review"))]
    RequestReview {
        #[arg(long, help = t("agent.number"))]
        number: u64,
        #[arg(long, help = t("agent.pr.reviewers"))]
        reviewers: Option<String>,
        #[arg(long, help = t("agent.pr.team_reviewers"))]
        teams: Option<String>,
    },
    #[command(about = t("agent.pr.status"))]
    Status {
        #[arg(long, help = t("agent.number"))]
        number: u64,
        #[arg(long, help = t("agent.pr.status.json"))]
        json: bool,
    },
    #[command(about = t("agent.pr.view"))]
    View {
        #[arg(long, help = t("agent.number"))]
        number: u64,
        #[arg(long, help = t("agent.json"))]
        json: bool,
    },
    #[command(about = t("agent.pr.comments"))]
    Comments {
        #[arg(long, help = t("agent.number"))]
        number: u64,
        #[arg(long, default_value_t = 30, help = t("agent.comments.limit"))]
        limit: u32,
        #[arg(long, help = t("agent.json"))]
        json: bool,
    },
    #[command(about = t("agent.pr.list"))]
    List {
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

#[derive(Subcommand, Debug)]
pub enum CiCmd {
    #[command(about = t("agent.ci.runs"))]
    Runs {
        #[arg(long = "ref", help = t("agent.ci.runs.ref"))]
        git_ref: String,
    },
    #[command(about = t("agent.ci.jobs"))]
    Jobs {
        #[arg(long, help = t("agent.number"))]
        number: Option<u64>,
        #[arg(long, help = t("agent.ci.run_id"))]
        run_id: Option<u64>,
    },
    #[command(about = t("agent.ci.rerun"))]
    Rerun {
        #[arg(long, help = t("agent.ci.run_id"))]
        run_id: u64,
        #[arg(long, help = t("agent.ci.rerun.all"))]
        all: bool,
    },
    #[command(about = t("agent.ci.cancel"))]
    Cancel {
        #[arg(long, help = t("agent.ci.run_id"))]
        run_id: u64,
    },
    #[command(about = t("agent.ci.log"))]
    Log {
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

#[derive(Subcommand, Debug)]
pub enum IssueCmd {
    #[command(about = t("agent.issue.create"))]
    Create {
        #[arg(long, help = t("agent.issue.title"))]
        title: String,
        #[arg(long, default_value = "", help = t("agent.body"))]
        body: String,
        #[arg(long, help = t("agent.issue.labels"))]
        labels: Option<String>,
    },
    #[command(about = t("agent.issue.comment"))]
    Comment {
        #[arg(long, help = t("agent.number"))]
        number: u64,
        #[arg(long, help = t("agent.body"))]
        body: String,
    },
    #[command(about = t("agent.issue.close"))]
    Close {
        #[arg(long, help = t("agent.number"))]
        number: u64,
    },
    #[command(about = t("agent.issue.reopen"))]
    Reopen {
        #[arg(long, help = t("agent.number"))]
        number: u64,
    },
    #[command(about = t("agent.issue.label"))]
    Label {
        #[arg(long, help = t("agent.number"))]
        number: u64,
        #[arg(long, help = t("agent.issue.labels"))]
        labels: String,
    },
    #[command(about = t("agent.issue.unlabel"))]
    Unlabel {
        #[arg(long, help = t("agent.number"))]
        number: u64,
        #[arg(long, help = t("agent.issue.unlabel.labels"))]
        labels: String,
    },
    #[command(about = t("agent.issue.assign"))]
    Assign {
        #[arg(long, help = t("agent.number"))]
        number: u64,
        #[arg(long, help = t("agent.issue.assignees"))]
        assignees: String,
    },
    #[command(about = t("agent.issue.unassign"))]
    Unassign {
        #[arg(long, help = t("agent.number"))]
        number: u64,
        #[arg(long, help = t("agent.issue.unassign.assignees"))]
        assignees: String,
    },
    #[command(about = t("agent.issue.view"))]
    View {
        #[arg(long, help = t("agent.number"))]
        number: u64,
        #[arg(long, help = t("agent.json"))]
        json: bool,
    },
    #[command(about = t("agent.issue.comments"))]
    Comments {
        #[arg(long, help = t("agent.number"))]
        number: u64,
        #[arg(long, default_value_t = 30, help = t("agent.comments.limit"))]
        limit: u32,
        #[arg(long, help = t("agent.json"))]
        json: bool,
    },
    #[command(about = t("agent.issue.list"))]
    List {
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

#[derive(Subcommand, Debug)]
pub enum ReleaseCmd {
    #[command(about = t("agent.release.create"))]
    Create {
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
    #[command(about = t("agent.release.edit"))]
    Edit {
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
    #[command(about = t("agent.release.view"))]
    View {
        #[arg(long, help = t("agent.release.tag"))]
        tag: String,
    },
    #[command(about = t("agent.release.list"))]
    List {
        #[arg(long, default_value_t = 20, help = t("agent.release.limit"))]
        limit: u32,
    },
}

#[derive(Subcommand, Debug)]
pub enum RepoCmd {
    #[command(about = t("agent.repo.vocabulary"))]
    Vocabulary,
}

#[derive(Subcommand, Debug)]
pub enum ProjectCmd {
    #[command(about = t("agent.project.add_item"))]
    AddItem {
        #[arg(long, help = t("agent.project.project_id"))]
        project_id: String,
        #[arg(long, help = t("agent.project.content_id"))]
        content_id: String,
    },
    #[command(about = t("agent.project.update_item"))]
    UpdateItem {
        #[arg(long, help = t("agent.project.project_id"))]
        project_id: String,
        #[arg(long, help = t("agent.project.item_id"))]
        item_id: String,
        #[arg(long, help = t("agent.project.field_id"))]
        field_id: String,
        #[arg(long, help = t("agent.project.update_item.value"))]
        value: String,
    },
    #[command(about = t("agent.project.list"))]
    List {
        #[arg(long, help = t("agent.project.project_id"))]
        project_id: String,
        #[arg(long, default_value_t = 20)]
        first: u32,
    },
    #[command(about = t("agent.project.fields"))]
    Fields {
        #[arg(long, help = t("agent.project.project_id"))]
        project_id: String,
        #[arg(long, default_value_t = 50)]
        first: u32,
    },
}
