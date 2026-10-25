use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::command::{bin_exists, resolve_bin, run_cmd_capture, spawn_allowed, CmdOutput};
use crate::error::Result;

/// Acción de solo lectura que se puede elevar con pkexec.
/// Nunca es un string libre: binario y argumentos viven acá.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegedAction {
    NftList,
    ConntrackList,
    IptablesSave,
    IptablesList,
    JournalResolved,
    SsList,
    Traceroute,
}

impl PrivilegedAction {
    pub fn from_bin(binary: &str) -> Option<Self> {
        match binary {
            "nft" => Some(Self::NftList),
            "conntrack" => Some(Self::ConntrackList),
            "iptables-save" => Some(Self::IptablesSave),
            "iptables" => Some(Self::IptablesList),
            "journalctl" => Some(Self::JournalResolved),
            "ss" => Some(Self::SsList),
            "traceroute" | "traceroute6" => Some(Self::Traceroute),
            _ => None,
        }
    }

    pub const fn bin(self) -> &'static str {
        match self {
            Self::NftList => "nft",
            Self::ConntrackList => "conntrack",
            Self::IptablesSave => "iptables-save",
            Self::IptablesList => "iptables",
            Self::JournalResolved => "journalctl",
            Self::SsList => "ss",
            Self::Traceroute => "traceroute",
        }
    }

    pub const fn args(self) -> &'static [&'static str] {
        match self {
            Self::NftList => &["list", "ruleset"],
            Self::ConntrackList => &["-L"],
            Self::IptablesSave => &["-c"],
            Self::IptablesList => &["-S"],
            Self::JournalResolved => &[
                "-u",
                "systemd-resolved",
                "-b",
                "--no-pager",
                "-o",
                "cat",
                "-n",
                "4000",
            ],
            Self::SsList => &["-H", "-tunap"],
            Self::Traceroute => &["-n", "-q", "1", "-w", "2"],
        }
    }

    pub const fn timeout(self) -> Duration {
        Duration::from_secs(120)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElevateError {
    Cancelled,
    AgentMissing,
    PkexecMissing,
    TargetMissing(String),
    Command(String),
}

impl ElevateError {
    pub const CANCELLED: &'static str = "Cancelaste el diálogo de contraseña. No se ejecutó nada.";
    pub const AGENT_MISSING: &'static str =
        "No hay agente de polkit o no se pudo autorizar (pkexec 127). Instalá policykit-1 y un agente de autenticación. Señal no corre como root.";
    pub const PKEXEC_MISSING: &'static str =
        "No está `pkexec`. En Ubuntu: sudo apt install policykit-1. Señal no corre como root.";

    pub fn from_output(out: CmdOutput) -> std::result::Result<CmdOutput, Self> {
        if out.success {
            return Ok(out);
        }
        match out.code {
            Some(126) => Err(Self::Cancelled),
            Some(127) => Err(Self::AgentMissing),
            _ => Ok(out),
        }
    }

    pub fn user_message(&self) -> String {
        match self {
            Self::Cancelled => Self::CANCELLED.to_string(),
            Self::AgentMissing => Self::AGENT_MISSING.to_string(),
            Self::PkexecMissing => Self::PKEXEC_MISSING.to_string(),
            Self::TargetMissing(bin) => format!("No está el binario `{bin}`."),
            Self::Command(detalle) => detalle.clone(),
        }
    }

    pub fn is_user_message(text: &str) -> bool {
        text == Self::CANCELLED
            || text == Self::AGENT_MISSING
            || text == Self::PKEXEC_MISSING
            || text.starts_with("No está el binario `")
    }
}

/// Elevación vía el camino existente (`resolve_bin` + `run_cmd_capture` / `spawn_allowed`).
pub struct Pkexec;

impl Pkexec {
    pub fn argv(target: &Path, args: &[&str]) -> Vec<String> {
        let mut argv = Vec::with_capacity(args.len() + 1);
        argv.push(target.to_string_lossy().into_owned());
        argv.extend(args.iter().copied().map(str::to_string));
        argv
    }

    pub fn capture(action: PrivilegedAction) -> std::result::Result<CmdOutput, ElevateError> {
        let argv = Self::prepare_argv(action.bin(), action.args())?;
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        let out = run_cmd_capture("pkexec", &refs, action.timeout())
            .map_err(|e| ElevateError::Command(e.to_string()))?;
        ElevateError::from_output(out)
    }

    pub fn spawn(
        bin: &str,
        args: &[&str],
    ) -> std::result::Result<std::process::Child, ElevateError> {
        let argv = Self::prepare_argv(bin, args)?;
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        spawn_allowed("pkexec", &refs, Duration::from_secs(120))
            .map_err(|e| ElevateError::Command(e.to_string()))
    }

    fn prepare_argv(bin: &str, args: &[&str]) -> std::result::Result<Vec<String>, ElevateError> {
        if !bin_exists("pkexec") {
            return Err(ElevateError::PkexecMissing);
        }
        let target = resolve_bin(bin).map_err(|_| ElevateError::TargetMissing(bin.to_string()))?;
        Ok(Self::argv(&target, args))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivilegeHint {
    pub binary: String,
    pub capability: String,
    pub why: String,
    pub action: Option<PrivilegedAction>,
    pub commands: Vec<String>,
    pub polkit_note: String,
}

impl PrivilegeHint {
    fn new(binary: &str, capability: &str, why: String, polkit_note: &str) -> Self {
        Self {
            binary: binary.to_string(),
            capability: capability.to_string(),
            why,
            action: PrivilegedAction::from_bin(binary),
            commands: hint_commands(binary),
            polkit_note: polkit_note.to_string(),
        }
    }
}

fn hint_commands(binary: &str) -> Vec<String> {
    match binary {
        "ss" => vec!["sudo ss -tunap".into()],
        "tracepath" | "tracepath6" => vec![format!("sudo {binary} -n <destino>")],
        "traceroute" | "traceroute6" => vec!["sudo tracepath -n <destino>".into()],
        _ => vec![],
    }
}

pub fn is_permission_error(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    t.contains("operation not permitted")
        || t.contains("permission denied")
        || t.contains("must be root")
        || t.contains("you need to be root")
        || t.contains("you must be root")
        || t.contains("need to be root")
        || t.contains("not authorized")
        || t.contains("autoriz")
        || t.contains("cap_net_admin")
        || t.contains("netlink: error")
        || t.contains("netlink error")
        || (t.contains("denied") && t.contains("net"))
}

pub fn is_permission_output(out: &CmdOutput) -> bool {
    if out.success {
        return false;
    }
    is_permission_error(&out.combined())
        || (matches!(
            out.code,
            Some(1) | Some(4) | Some(13) | Some(126) | Some(255)
        ) && out.stderr.to_ascii_lowercase().contains("permit"))
}

pub fn privilege_hint(binary: &str, capability: &str) -> PrivilegeHint {
    match binary {
        "nft" => PrivilegeHint::new(
            "nft",
            "CAP_NET_ADMIN",
            "Leer `nft list ruleset` habla con nf_tables vía netlink. El kernel lo deja a root o a quien tenga CAP_NET_ADMIN. Señal corre como tu usuario y no va a tocar las reglas: solo las quiere listar.".into(),
            "Un clic abre el diálogo de contraseña del sistema (pkexec). Señal no corre como root y no escribe reglas.",
        ),
        "conntrack" => PrivilegeHint::new(
            "conntrack",
            "CAP_NET_ADMIN",
            "La tabla de conntrack (NAT y estados) vive en el kernel. `conntrack -L` y `/proc/net/nf_conntrack` suelen pedir CAP_NET_ADMIN. Sin eso no podemos ver traducciones SNAT/DNAT.".into(),
            "Un clic abre el diálogo de contraseña del sistema (pkexec). Señal nunca escribe en conntrack.",
        ),
        "iptables" | "iptables-save" => PrivilegeHint::new(
            binary,
            "CAP_NET_ADMIN",
            format!(
                "`{binary}` lee el filtrado legacy. En Ubuntu reciente suele ser un wrapper sobre nftables, y igual pide CAP_NET_ADMIN para listar."
            ),
            "Un clic abre el diálogo de contraseña del sistema (pkexec). Preferí nft si está. No ejecutes Señal como root.",
        ),
        "traceroute" | "traceroute6" => PrivilegeHint::new(
            binary,
            "CAP_NET_RAW",
            format!(
                "`{binary}` con ICMP suele necesitar CAP_NET_RAW (como ping). En Ubuntu el default es `tracepath` (UDP) y casi siempre anda sin root: Señal lo intenta primero."
            ),
            "Un clic abre el diálogo de contraseña del sistema (pkexec) y relanza traceroute. Si cancelás, no pasa nada.",
        ),
        "tracepath" | "tracepath6" => PrivilegeHint::new(
            binary,
            "CAP_NET_RAW",
            format!(
                "`{binary}` (UDP) casi siempre anda sin root. Si pidió privilegios, en una terminal tuya: sudo {binary} -n <destino>."
            ),
            "Señal no ejecuta ese sudo. Si traceroute pide raw, el botón eleva traceroute con pkexec.",
        ),
        "journalctl" => PrivilegeHint::new(
            "journalctl",
            "systemd-journal (grupo)",
            "El journal de systemd-resolved es del sistema. Tu usuario, por defecto, no lo lee; por eso no aparecen consultas DNS desde el arranque. No es CAP_NET_ADMIN: es el ACL del journal. Sin permiso, Señal no puede reconstruir dominios desde el boot.".into(),
            "Un clic lee el journal con pkexec. No hace falta agregarte al grupo systemd-journal ni abrir Señal como root.",
        ),
        "resolvectl" => PrivilegeHint::new(
            "resolvectl",
            "systemd-resolved",
            "`resolvectl monitor` a veces exige más privilegios. Sin eso no hay DNS en vivo mientras Señal está abierta. Señal no corre como root.".into(),
            "El historial de esta sesión (sockets a :53) igual se acumula. Si el journal pide permiso, usá el botón de administrador.",
        ),
        "ss" => PrivilegeHint::new(
            "ss",
            "CAP_NET_ADMIN",
            "Listar sockets con `ss -tunap` a veces pide privilegios para ver procesos de otros usuarios. Señal solo lista: no cierra conexiones.".into(),
            "Un clic abre el diálogo de contraseña del sistema (pkexec). Señal no corre como root.",
        ),
        _ => PrivilegeHint::new(
            binary,
            capability,
            format!(
                "Señal no corre como root. El comando `{binary}` pidió privilegios ({capability}). No vamos a ejecutarlo con sudo ni a cambiar el sistema."
            ),
            "Si hay una acción conocida, un clic pide la contraseña del sistema con pkexec. No hace falta lanzar Señal con sudo.",
        ),
    }
}

/// Corre un binario allowlisted; si `elevate` apunta a ese mismo binario, lo envuelve en pkexec.
pub fn capture_maybe(
    name: &str,
    args: &[&str],
    timeout: Duration,
    elevate: Option<PrivilegedAction>,
) -> Result<CmdOutput> {
    if let Some(action) = elevate.filter(|a| a.bin() == name) {
        Pkexec::capture(action).map_err(|e| crate::error::CoreError::Forbidden(e.user_message()))
    } else {
        run_cmd_capture(name, args, timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::validate_host;

    #[test]
    fn detects_permission_phrases() {
        assert!(is_permission_error(
            "netlink: Error: Operation not permitted"
        ));
        assert!(is_permission_error("conntrack: Permission denied"));
        assert!(is_permission_error("You must be root"));
        assert!(!is_permission_error("table inet filter {"));
    }

    #[test]
    fn ss_and_tracepath_hints_include_args() {
        let ss = privilege_hint("ss", "CAP_NET_ADMIN");
        assert!(ss.commands.iter().any(|c| c == "sudo ss -tunap"));
        assert!(!ss.commands.iter().any(|c| c == "sudo ss"));
        let tp = privilege_hint("tracepath", "CAP_NET_RAW");
        assert!(tp
            .commands
            .iter()
            .any(|c| c.contains("tracepath -n <destino>")));
        assert!(!tp.commands.iter().any(|c| c == "sudo tracepath"));
    }

    #[test]
    fn hint_has_action_not_sudo_setcap() {
        for bin in [
            "nft",
            "conntrack",
            "iptables-save",
            "iptables",
            "journalctl",
            "ss",
            "traceroute",
        ] {
            let h = privilege_hint(bin, "CAP_NET_ADMIN");
            assert_eq!(h.action, PrivilegedAction::from_bin(bin));
            let blob = format!("{} {}", h.why, h.polkit_note);
            assert!(!blob.contains("setcap"), "{bin}: {blob}");
            assert!(
                !blob.contains("sudo setcap")
                    && !blob.contains("sudo nft")
                    && !blob.contains("sudo conntrack"),
                "{bin}: {blob}"
            );
        }
    }

    #[test]
    fn pkexec_argv_is_fixed_allowlisted() {
        let argv = Pkexec::argv(Path::new("/usr/sbin/nft"), PrivilegedAction::NftList.args());
        assert_eq!(argv, vec!["/usr/sbin/nft", "list", "ruleset"]);
        assert_eq!(
            Pkexec::argv(
                Path::new("/usr/sbin/conntrack"),
                PrivilegedAction::ConntrackList.args()
            ),
            vec!["/usr/sbin/conntrack", "-L"]
        );
        assert_eq!(
            Pkexec::argv(
                Path::new("/usr/sbin/iptables-save"),
                PrivilegedAction::IptablesSave.args()
            ),
            vec!["/usr/sbin/iptables-save", "-c"]
        );
        assert_eq!(
            Pkexec::argv(
                Path::new("/usr/bin/journalctl"),
                PrivilegedAction::JournalResolved.args()
            ),
            vec![
                "/usr/bin/journalctl",
                "-u",
                "systemd-resolved",
                "-b",
                "--no-pager",
                "-o",
                "cat",
                "-n",
                "4000"
            ]
        );
        for action in [
            PrivilegedAction::NftList,
            PrivilegedAction::ConntrackList,
            PrivilegedAction::IptablesSave,
            PrivilegedAction::IptablesList,
            PrivilegedAction::JournalResolved,
            PrivilegedAction::SsList,
        ] {
            for arg in action.args() {
                assert!(!arg.contains(';'), "{arg}");
                assert!(!arg.contains('$'), "{arg}");
                assert!(!arg.contains('|'), "{arg}");
            }
        }
    }

    #[test]
    fn traceroute_argv_appends_validated_host_not_shell() {
        let dest = validate_host("8.8.8.8").unwrap();
        let flags = PrivilegedAction::Traceroute.args();
        let mut args: Vec<&str> = flags.to_vec();
        args.push("--");
        args.push(dest.as_str());
        let argv = Pkexec::argv(Path::new("/usr/bin/traceroute"), &args);
        assert_eq!(
            argv,
            vec![
                "/usr/bin/traceroute",
                "-n",
                "-q",
                "1",
                "-w",
                "2",
                "--",
                "8.8.8.8"
            ]
        );
        assert!(validate_host("8.8.8.8; id").is_err());
        assert!(validate_host("example.com && reboot").is_err());
    }

    #[test]
    fn maps_pkexec_cancel_and_missing_agent() {
        let cancelled = CmdOutput {
            stdout: String::new(),
            stderr: "Error executing command as another user: Request dismissed".into(),
            success: false,
            code: Some(126),
        };
        assert_eq!(
            ElevateError::from_output(cancelled).unwrap_err(),
            ElevateError::Cancelled
        );
        assert_eq!(
            ElevateError::Cancelled.user_message(),
            ElevateError::CANCELLED
        );

        let agent = CmdOutput {
            stdout: String::new(),
            stderr: "polkit agent not found".into(),
            success: false,
            code: Some(127),
        };
        assert_eq!(
            ElevateError::from_output(agent).unwrap_err(),
            ElevateError::AgentMissing
        );
        assert!(ElevateError::is_user_message(ElevateError::CANCELLED));
        assert!(ElevateError::is_user_message(ElevateError::AGENT_MISSING));
        assert!(ElevateError::is_user_message(ElevateError::PKEXEC_MISSING));
    }

    #[test]
    fn success_and_other_codes_pass_through() {
        let ok = CmdOutput {
            stdout: "table inet filter {}".into(),
            stderr: String::new(),
            success: true,
            code: Some(0),
        };
        assert!(ElevateError::from_output(ok).is_ok());

        let other = CmdOutput {
            stdout: String::new(),
            stderr: "syntax error".into(),
            success: false,
            code: Some(1),
        };
        let passed = ElevateError::from_output(other).expect("1 no es cancel");
        assert!(!passed.success);
        assert_eq!(passed.code, Some(1));
    }

    #[test]
    fn ss_and_tracepath_hints_include_args() {
        let ss = privilege_hint("ss", "CAP_NET_ADMIN");
        assert!(ss.commands.iter().any(|c| c == "sudo ss -tunap"));
        assert!(!ss.commands.iter().any(|c| c == "sudo ss"));
        let tp = privilege_hint("tracepath", "CAP_NET_RAW");
        assert!(tp
            .commands
            .iter()
            .any(|c| c.contains("tracepath -n <destino>")));
        assert!(!tp.commands.iter().any(|c| c == "sudo tracepath"));
    }
}
