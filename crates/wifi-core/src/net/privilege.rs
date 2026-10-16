use serde::{Deserialize, Serialize};

use crate::command::CmdOutput;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivilegeHint {
    pub binary: String,
    pub capability: String,
    pub why: String,
    pub commands: Vec<String>,
    pub polkit_note: String,
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
        "nft" => nft_hint(),
        "conntrack" => conntrack_hint(),
        "iptables" | "iptables-save" => iptables_hint(binary),
        "traceroute" | "traceroute6" => traceroute_hint(binary),
        "journalctl" => journal_hint(),
        _ => generic_hint(binary, capability),
    }
}

fn generic_hint(binary: &str, capability: &str) -> PrivilegeHint {
    let cap = capability.to_ascii_lowercase();
    PrivilegeHint {
        binary: binary.to_string(),
        capability: capability.to_string(),
        why: format!(
            "Señal no corre como root. El comando `{binary}` pidió privilegios ({capability}). No vamos a ejecutarlo con sudo ni a cambiar el sistema."
        ),
        commands: vec![
            format!("sudo setcap {cap}+ep \"$(command -v {binary})\""),
            "# si solo querés ver la salida una vez:".into(),
            format!("sudo {binary}"),
        ],
        polkit_note: "Tampoco hace falta lanzar Señal con sudo: es más riesgoso y no está soportado.".to_string(),
    }
}

fn nft_hint() -> PrivilegeHint {
    PrivilegeHint {
        binary: "nft".into(),
        capability: "CAP_NET_ADMIN".into(),
        why: "Leer `nft list ruleset` habla con nf_tables vía netlink. El kernel lo deja a root o a quien tenga CAP_NET_ADMIN. Señal corre como tu usuario y no va a tocar las reglas: solo las quiere listar.".into(),
        commands: vec![
            "sudo setcap cap_net_admin+ep \"$(command -v nft)\"".into(),
            "# alternativa puntual (no deja la capability en el binario):".into(),
            "sudo nft list ruleset".into(),
        ],
        polkit_note: "Algunas distros tienen reglas polkit para nft. No hace falta (ni conviene) abrir Señal con sudo.".into(),
    }
}

fn conntrack_hint() -> PrivilegeHint {
    PrivilegeHint {
        binary: "conntrack".into(),
        capability: "CAP_NET_ADMIN".into(),
        why: "La tabla de conntrack (NAT y estados) vive en el kernel. `conntrack -L` y `/proc/net/nf_conntrack` suelen pedir CAP_NET_ADMIN. Sin eso no podemos ver traducciones SNAT/DNAT.".into(),
        commands: vec![
            "sudo setcap cap_net_admin+ep \"$(command -v conntrack)\"".into(),
            "# alternativa puntual:".into(),
            "sudo conntrack -L".into(),
            "# o, si el procfs está abierto para tu usuario (poco habitual):".into(),
            "cat /proc/net/nf_conntrack".into(),
        ],
        polkit_note: "Señal nunca va a escribir en conntrack (`-D`, `-I`, flush, etc.). Solo lista.".into(),
    }
}

fn iptables_hint(binary: &str) -> PrivilegeHint {
    PrivilegeHint {
        binary: binary.into(),
        capability: "CAP_NET_ADMIN".into(),
        why: format!(
            "`{binary}` lee el filtrado legacy. En Ubuntu reciente suele ser un wrapper sobre nftables, y igual pide CAP_NET_ADMIN para listar."
        ),
        commands: vec![
            format!("sudo setcap cap_net_admin+ep \"$(command -v {binary})\""),
            format!("sudo {binary} -S"),
            "sudo iptables-save -c".into(),
        ],
        polkit_note: "Preferí nft si está. No ejecutes Señal como root.".into(),
    }
}

fn traceroute_hint(binary: &str) -> PrivilegeHint {
    PrivilegeHint {
        binary: binary.into(),
        capability: "CAP_NET_RAW".into(),
        why: format!(
            "`{binary}` con ICMP suele necesitar CAP_NET_RAW (como ping). `tracepath` usa UDP y casi siempre anda sin root: lo intentamos de fallback."
        ),
        commands: vec![
            format!("sudo setcap cap_net_raw+ep \"$(command -v {binary})\""),
            "tracepath -n <destino>".into(),
        ],
        polkit_note: "Si traceroute falla y tracepath existe, Señal usa tracepath solo.".into(),
    }
}

fn journal_hint() -> PrivilegeHint {
    PrivilegeHint {
        binary: "journalctl".into(),
        capability: "systemd-journal (grupo)".into(),
        why: "El journal de systemd-resolved es del sistema. Tu usuario, por defecto, no lo lee; por eso no aparecen consultas DNS desde el arranque. No es CAP_NET_ADMIN: es el ACL del journal.".into(),
        commands: vec![
            "sudo usermod -aG systemd-journal \"$USER\"".into(),
            "# cerrá sesión y volvé a entrar, después:".into(),
            "journalctl -u systemd-resolved -b --no-pager".into(),
        ],
        polkit_note: "Eso cambia el grupo de tu usuario (lo tenés que hacer vos). Señal no lo ejecuta.".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_permission_phrases() {
        assert!(is_permission_error(
            "netlink: Error: Operation not permitted"
        ));
        assert!(is_permission_error("conntrack: Permission denied"));
        assert!(is_permission_error("You must be root"));
        assert!(!is_permission_error("table inet filter {"));
    }
}
