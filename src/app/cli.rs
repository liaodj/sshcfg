use clap::{ArgGroup, Args, Parser, Subcommand};

use crate::core::template::TemplateKind;

#[derive(Debug, Parser)]
#[command(
    name = "sshcfg",
    version,
    about = "Manage SSH config entries with a managed config.d layout"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Init(InitArgs),
    List(ListArgs),
    Show(ShowArgs),
    Meta(MetaArgs),
    Add(AddArgs),
    Edit(EditArgs),
    Duplicate(DuplicateArgs),
    Order(OrderArgs),
    Delete(DeleteArgs),
    Template(TemplateArgs),
    Validate(ValidateArgs),
    Doctor,
    Tui,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    #[arg(long)]
    pub migrate: bool,
}

#[derive(Debug, Clone, Args, Default)]
pub struct ValidateArgs {
    #[arg(
        long = "ssh-g",
        help = "Run local `ssh -G` checks for exact Host entries and compare stable resolved fields"
    )]
    pub ssh_g: bool,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    #[command(flatten)]
    pub filter: MetadataFilterArgs,
}

#[derive(Debug, Args)]
#[command(
    after_help = "Examples:\n  sshcfg show server-a\n  sshcfg show server-a --merged\n  sshcfg show server-a --merged --match-session-type exec --match-command \"git fetch\"\n  sshcfg show server-a --merged --match-canonical\n  sshcfg show server-a --merged --match-tag ops --match-local-network 192.168.1.42\n  sshcfg show server-a --merged --match-user deploy --match-local-user ubuntu --match-ssh-version OpenSSH_9.6p1"
)]
pub struct ShowArgs {
    pub host: String,

    #[arg(long)]
    pub merged: bool,

    #[arg(long = "match-tag", requires = "merged")]
    pub match_tag: Option<String>,

    #[arg(long = "match-ssh-version", requires = "merged")]
    pub match_ssh_version: Option<String>,

    #[arg(long = "match-user", requires = "merged")]
    pub match_user: Option<String>,

    #[arg(long = "match-local-user", requires = "merged")]
    pub match_local_user: Option<String>,

    #[arg(long = "match-session-type", requires = "merged")]
    pub match_session_type: Option<String>,

    #[arg(long = "match-command", requires = "merged")]
    pub match_command: Option<String>,

    #[arg(long = "match-local-network", requires = "merged")]
    pub match_local_networks: Vec<String>,

    #[arg(long = "match-canonical", requires = "merged")]
    pub match_canonical: bool,

    #[arg(long = "match-non-final", requires = "merged")]
    pub match_non_final: bool,
}

#[derive(Debug, Args)]
pub struct MetaArgs {
    #[command(subcommand)]
    pub command: MetaCommands,
}

#[derive(Debug, Subcommand)]
pub enum MetaCommands {
    Show(MetaShowArgs),
    SetNote(MetaNoteArgs),
    ClearNote(MetaTargetArgs),
    AddTag(MetaTagArgs),
    RemoveTag(MetaTagArgs),
    ClearTags(MetaTargetArgs),
    Bulk(MetaBulkArgs),
}

#[derive(Debug, Args)]
pub struct MetaTargetArgs {
    pub host: String,
}

#[derive(Debug, Args)]
pub struct MetaShowArgs {
    pub host: String,
}

#[derive(Debug, Args)]
pub struct MetaNoteArgs {
    pub host: String,
    pub note: String,
}

#[derive(Debug, Args)]
pub struct MetaTagArgs {
    pub host: String,
    pub tag: String,
}

#[derive(Debug, Clone, Args, Default)]
pub struct MetadataFilterArgs {
    #[arg(long, short)]
    pub query: Option<String>,

    #[arg(long = "tag")]
    pub tags: Vec<String>,

    #[arg(long)]
    pub has_note: bool,

    #[arg(long, value_enum)]
    pub template: Option<TemplateKind>,
}

#[derive(Debug, Clone, Args, Default)]
pub struct MetaBulkSelectorArgs {
    #[arg(long)]
    pub all: bool,

    #[command(flatten)]
    pub filter: MetadataFilterArgs,
}

#[derive(Debug, Args)]
pub struct MetaBulkArgs {
    #[command(subcommand)]
    pub command: MetaBulkCommands,
}

#[derive(Debug, Subcommand)]
pub enum MetaBulkCommands {
    SetNote(MetaBulkNoteArgs),
    ClearNote(MetaBulkTargetArgs),
    AddTag(MetaBulkTagArgs),
    RemoveTag(MetaBulkTagArgs),
    ClearTags(MetaBulkTargetArgs),
}

#[derive(Debug, Clone, Args)]
pub struct MetaBulkTargetArgs {
    #[command(flatten)]
    pub selector: MetaBulkSelectorArgs,
}

#[derive(Debug, Clone, Args)]
pub struct MetaBulkNoteArgs {
    #[command(flatten)]
    pub selector: MetaBulkSelectorArgs,
    pub note: String,
}

#[derive(Debug, Clone, Args)]
pub struct MetaBulkTagArgs {
    #[command(flatten)]
    pub selector: MetaBulkSelectorArgs,
    pub tag: String,
}

#[derive(Debug, Clone, Args)]
#[command(
    about = "Add a managed SSH entry",
    after_help = "Examples:\n  sshcfg add 172.16.7.226\n  sshcfg add server-a --hostname 172.16.7.226\n  sshcfg add tunnel-a --hostname 10.0.0.10 --remote-forward \"9090 127.0.0.1:90\"\n  sshcfg add server-a --ssh-tag ops\n  sshcfg add server-a --interactive"
)]
pub struct AddArgs {
    #[arg(help = "Host alias, exact target, or pattern to manage")]
    pub host: String,

    #[arg(long, short = 'i', help = "Open an interactive wizard before saving")]
    pub interactive: bool,

    #[arg(long)]
    pub hostname: Option<String>,

    #[arg(long)]
    pub user: Option<String>,

    #[arg(long)]
    pub port: Option<u16>,

    #[arg(long)]
    pub proxy_jump: Option<String>,

    #[arg(long = "identity-file")]
    pub identity_files: Vec<String>,

    #[arg(long = "local-forward")]
    pub local_forwards: Vec<String>,

    #[arg(long = "remote-forward")]
    pub remote_forwards: Vec<String>,

    #[arg(long)]
    pub strict_host_key_checking: Option<String>,

    #[arg(long)]
    pub user_known_hosts_file: Option<String>,

    #[arg(long)]
    pub host_key_algorithms: Option<String>,

    #[arg(long)]
    pub pubkey_accepted_algorithms: Option<String>,

    #[arg(long)]
    pub forward_agent: Option<String>,

    #[arg(long = "ssh-tag")]
    pub ssh_tag: Option<String>,

    #[arg(long, value_enum)]
    pub template: Option<TemplateKind>,

    #[arg(long)]
    pub order: Option<u16>,

    #[arg(
        long = "extra",
        value_name = "KEY=VALUE",
        help = "Add a custom SSH directive, repeatable"
    )]
    pub extras: Vec<String>,

    #[arg(long = "tag")]
    pub tags: Vec<String>,

    #[arg(long)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Args)]
#[command(
    about = "Edit a managed SSH entry",
    after_help = "Examples:\n  sshcfg edit server-a\n  sshcfg edit server-a --user builder\n  sshcfg edit tunnel-a --remote-forward \"9090 127.0.0.1:90\"\n  sshcfg edit tunnel-a --clear-remote-forwards\n  sshcfg edit server-a --ssh-tag ops\n  sshcfg edit server-a --interactive\n  sshcfg edit server-a --clear-template"
)]
pub struct EditArgs {
    pub host: String,

    #[arg(long, short = 'i', help = "Open an interactive editor before saving")]
    pub interactive: bool,

    #[arg(long = "set-host")]
    pub new_host: Option<String>,

    #[arg(long)]
    pub hostname: Option<String>,

    #[arg(long)]
    pub clear_hostname: bool,

    #[arg(long)]
    pub user: Option<String>,

    #[arg(long)]
    pub clear_user: bool,

    #[arg(long)]
    pub port: Option<u16>,

    #[arg(long)]
    pub clear_port: bool,

    #[arg(long)]
    pub proxy_jump: Option<String>,

    #[arg(long)]
    pub clear_proxy_jump: bool,

    #[arg(long = "identity-file")]
    pub identity_files: Vec<String>,

    #[arg(long = "clear-identity-files")]
    pub clear_identity_files: bool,

    #[arg(long = "local-forward")]
    pub local_forwards: Vec<String>,

    #[arg(long = "clear-local-forwards")]
    pub clear_local_forwards: bool,

    #[arg(long = "remote-forward")]
    pub remote_forwards: Vec<String>,

    #[arg(long = "clear-remote-forwards")]
    pub clear_remote_forwards: bool,

    #[arg(long)]
    pub strict_host_key_checking: Option<String>,

    #[arg(long)]
    pub clear_strict_host_key_checking: bool,

    #[arg(long)]
    pub user_known_hosts_file: Option<String>,

    #[arg(long)]
    pub clear_user_known_hosts_file: bool,

    #[arg(long)]
    pub host_key_algorithms: Option<String>,

    #[arg(long)]
    pub clear_host_key_algorithms: bool,

    #[arg(long)]
    pub pubkey_accepted_algorithms: Option<String>,

    #[arg(long)]
    pub clear_pubkey_accepted_algorithms: bool,

    #[arg(long)]
    pub forward_agent: Option<String>,

    #[arg(long)]
    pub clear_forward_agent: bool,

    #[arg(long = "ssh-tag")]
    pub ssh_tag: Option<String>,

    #[arg(long = "clear-ssh-tag")]
    pub clear_ssh_tag: bool,

    #[arg(long, value_enum)]
    pub template: Option<TemplateKind>,

    #[arg(long = "clear-template")]
    pub clear_template: bool,

    #[arg(long)]
    pub order: Option<u16>,

    #[arg(
        long = "extra",
        value_name = "KEY=VALUE",
        help = "Replace custom SSH directives, repeatable"
    )]
    pub extras: Vec<String>,

    #[arg(long = "clear-extra")]
    pub clear_extras: bool,

    #[arg(long = "tag")]
    pub tags: Vec<String>,

    #[arg(long = "clear-tags")]
    pub clear_tags: bool,

    #[arg(long)]
    pub note: Option<String>,

    #[arg(long = "clear-note")]
    pub clear_note: bool,
}

#[derive(Debug, Clone, Args)]
#[command(
    about = "Duplicate a managed SSH entry",
    after_help = "Examples:\n  sshcfg duplicate server-a server-b --hostname 10.0.0.11\n  sshcfg duplicate 172.16.7.226 172.16.7.227\n  sshcfg duplicate jump-a jump-b --keep-hostname"
)]
pub struct DuplicateArgs {
    #[arg(help = "Existing managed host alias or pattern to copy from")]
    pub source: String,

    #[arg(help = "New managed host alias, target, or pattern to create")]
    pub host: String,

    #[arg(long, help = "Override the duplicated HostName")]
    pub hostname: Option<String>,

    #[arg(
        long,
        help = "Keep the source HostName when duplicating to a new alias or pattern"
    )]
    pub keep_hostname: bool,

    #[arg(long, help = "Explicit order for the duplicated entry")]
    pub order: Option<u16>,
}

#[derive(Debug, Clone, Args)]
#[command(
    about = "Change managed SSH entry order",
    after_help = "Examples:\n  sshcfg order server-a --before jump-a\n  sshcfg order --tag prod --after jump-a\n  sshcfg order --query edge --first\n  sshcfg order server-a\n  sshcfg order server-a --interactive",
    group(
        ArgGroup::new("destination")
            .args(["before", "after", "first", "last"])
    )
)]
pub struct OrderArgs {
    #[arg(help = "Managed host alias to reorder")]
    pub host: Option<String>,

    #[arg(long, help = "Allow an empty selector and target all managed entries")]
    pub all: bool,

    #[command(flatten)]
    pub filter: MetadataFilterArgs,

    #[arg(long, short = 'i', help = "Open an interactive reorder guide")]
    pub interactive: bool,

    #[arg(long)]
    pub before: Option<String>,

    #[arg(long)]
    pub after: Option<String>,

    #[arg(long)]
    pub first: bool,

    #[arg(long)]
    pub last: bool,
}

#[derive(Debug, Clone, Args)]
#[command(
    about = "Delete a managed SSH entry",
    after_help = "Examples:\n  sshcfg delete server-a\n  sshcfg delete server-a -y\n  sshcfg delete --tag prod --has-note\n  sshcfg delete --all -y"
)]
pub struct DeleteArgs {
    #[arg(help = "Managed host alias to delete")]
    pub host: Option<String>,

    #[arg(long, help = "Allow an empty selector and target all managed entries")]
    pub all: bool,

    #[command(flatten)]
    pub filter: MetadataFilterArgs,

    #[arg(long, short = 'y')]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct TemplateArgs {
    #[command(subcommand)]
    pub command: TemplateCommands,
}

#[derive(Debug, Subcommand)]
pub enum TemplateCommands {
    List,
}
