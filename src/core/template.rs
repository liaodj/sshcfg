use clap::ValueEnum;

use crate::core::model::HostEntry;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TemplateKind {
    Embedded,
    Legacy,
    Vps,
    Jump,
    Forward,
}

#[derive(Debug, Clone, Copy)]
pub struct TemplateInfo {
    pub kind: TemplateKind,
    pub summary: &'static str,
    pub directives: &'static [(&'static str, &'static str)],
}

const EMBEDDED_DIRECTIVES: [(&str, &str); 2] = [
    ("StrictHostKeyChecking", "no"),
    ("UserKnownHostsFile", "/dev/null"),
];
const LEGACY_DIRECTIVES: [(&str, &str); 4] = [
    ("StrictHostKeyChecking", "no"),
    ("UserKnownHostsFile", "/dev/null"),
    ("HostKeyAlgorithms", "+ssh-rsa"),
    ("PubkeyAcceptedAlgorithms", "+ssh-rsa"),
];
const VPS_DIRECTIVES: [(&str, &str); 0] = [];
const JUMP_DIRECTIVES: [(&str, &str); 0] = [];
const FORWARD_DIRECTIVES: [(&str, &str); 0] = [];

const TEMPLATE_INFOS: [TemplateInfo; 5] = [
    TemplateInfo {
        kind: TemplateKind::Embedded,
        summary: "Embedded devices / frequent reflashing",
        directives: &EMBEDDED_DIRECTIVES,
    },
    TemplateInfo {
        kind: TemplateKind::Legacy,
        summary: "Legacy SSH devices that still require ssh-rsa",
        directives: &LEGACY_DIRECTIVES,
    },
    TemplateInfo {
        kind: TemplateKind::Vps,
        summary: "Reserved for VPS presets such as IdentityFile",
        directives: &VPS_DIRECTIVES,
    },
    TemplateInfo {
        kind: TemplateKind::Jump,
        summary: "Reserved for jump-host presets such as ProxyJump",
        directives: &JUMP_DIRECTIVES,
    },
    TemplateInfo {
        kind: TemplateKind::Forward,
        summary: "Reserved for port-forward presets such as LocalForward",
        directives: &FORWARD_DIRECTIVES,
    },
];

impl TemplateKind {
    pub fn cli_name(self) -> &'static str {
        match self {
            Self::Embedded => "embedded",
            Self::Legacy => "legacy",
            Self::Vps => "vps",
            Self::Jump => "jump",
            Self::Forward => "forward",
        }
    }
}

pub fn parse_cli_name(value: &str) -> Option<TemplateKind> {
    match value.trim().to_ascii_lowercase().as_str() {
        "embedded" => Some(TemplateKind::Embedded),
        "legacy" => Some(TemplateKind::Legacy),
        "vps" => Some(TemplateKind::Vps),
        "jump" => Some(TemplateKind::Jump),
        "forward" => Some(TemplateKind::Forward),
        _ => None,
    }
}

pub fn template_infos() -> &'static [TemplateInfo] {
    &TEMPLATE_INFOS
}

pub fn apply_template(entry: &mut HostEntry, template: TemplateKind) {
    match template {
        TemplateKind::Embedded => {
            set_if_missing(&mut entry.strict_host_key_checking, "no");
            set_if_missing(&mut entry.user_known_hosts_file, "/dev/null");
        }
        TemplateKind::Legacy => {
            apply_template(entry, TemplateKind::Embedded);
            set_if_missing(&mut entry.host_key_algorithms, "+ssh-rsa");
            set_if_missing(&mut entry.pubkey_accepted_algorithms, "+ssh-rsa");
        }
        TemplateKind::Vps | TemplateKind::Jump | TemplateKind::Forward => {}
    }
}

fn set_if_missing(slot: &mut Option<String>, value: &str) {
    if slot.is_none() {
        *slot = Some(value.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::{TemplateKind, parse_cli_name, template_infos};

    #[test]
    fn template_catalog_lists_all_kinds() {
        let names: Vec<_> = template_infos()
            .iter()
            .map(|item| item.kind.cli_name())
            .collect();
        assert_eq!(
            names,
            vec![
                TemplateKind::Embedded.cli_name(),
                TemplateKind::Legacy.cli_name(),
                TemplateKind::Vps.cli_name(),
                TemplateKind::Jump.cli_name(),
                TemplateKind::Forward.cli_name(),
            ]
        );
    }

    #[test]
    fn parses_template_cli_names_case_insensitively() {
        assert_eq!(parse_cli_name("legacy"), Some(TemplateKind::Legacy));
        assert_eq!(parse_cli_name("EMBEDDED"), Some(TemplateKind::Embedded));
        assert_eq!(parse_cli_name("unknown"), None);
    }
}
