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
        "resolvectl" => resolvectl_hint(),
        _ => generic_hint(binary, capability),
    }
}

fn generic_hint(binary: &str, capability: &str) -> PrivilegeHint {
    let cap = capability.to_ascii_lowercase();
    let why = if cap.contains("net_admin") {
        format!(
            "Señal no corre como root. `{binary}` pidió {capability}. No vamos a ejecutarlo con sudo ni a ponerle setcap: CAP_NET_ADMIN sobre herramientas de netfilter deja a cualquier usuario local reescribir el firewall."
        )
    } else {
        format!(
            "Señal no corre como root. El comando `{binary}` pidió privilegios ({capability}). No vamos a ejecutarlo con sudo ni a cambiar el sistema."
        )
    };
    let commands = if cap.contains("net_admin") {
        vec![
            "# una sola vez, solo lectura, en una terminal tuya:".into(),
            format!("sudo {binary}"),
        ]
    } else {
        vec![
            "# una sola vez, en una terminal tuya (Señal no lo ejecuta):".into(),
            format!("sudo {binary}"),
        ]
    };
    PrivilegeHint {
        binary: binary.to_string(),
        capability: capability.to_string(),
        why,
        commands,
        polkit_note:
            "Tampoco hace falta lanzar Señal con sudo: es más riesgoso y no está soportado."
                .to_string(),
    }
}

fn nft_hint() -> PrivilegeHint {
    PrivilegeHint {
        binary: "nft".into(),
        capability: "CAP_NET_ADMIN".into(),
        why: "Leer `nft list ruleset` habla con nf_tables vía netlink. El kernel lo deja a root. Señal corre como tu usuario y no va a tocar las reglas. No recomendamos `setcap cap_net_admin` sobre `nft`: cualquier proceso de tu usuario podría entonces agregar, borrar o flushear reglas.".into(),
        commands: vec![
            "# una sola vez, solo lectura (Señal no lo ejecuta):".into(),
            "sudo nft list ruleset".into(),
        ],
        polkit_note: "Pegá esa salida si querés ver el ruleset. No hace falta (ni conviene) abrir Señal con sudo.".into(),
    }
}

fn conntrack_hint() -> PrivilegeHint {
    PrivilegeHint {
        binary: "conntrack".into(),
        capability: "CAP_NET_ADMIN".into(),
        why: "La tabla de conntrack (NAT y estados) vive en el kernel. `conntrack -L` suele pedir root. No recomendamos setcap CAP_NET_ADMIN sobre `conntrack`: con esa capability se puede borrar o inyectar entradas, no solo listar.".into(),
        commands: vec![
            "# una sola vez, solo lectura (Señal no lo ejecuta):".into(),
            "sudo conntrack -L".into(),
            "# si el procfs está abierto para tu usuario (poco habitual):".into(),
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
            "`{binary}` lee el filtrado legacy. En Ubuntu reciente suele ser un wrapper sobre nftables. Tampoco recomendamos setcap CAP_NET_ADMIN: dejaría reescribir el filtrado a cualquier usuario local."
        ),
        commands: vec![
            "# una sola vez, solo lectura (Señal no lo ejecuta):".into(),
            "sudo iptables-save -c".into(),
            "sudo iptables -S".into(),
        ],
        polkit_note: "Preferí nft si está. No ejecutes Señal como root.".into(),
    }
}

fn traceroute_hint(binary: &str) -> PrivilegeHint {
    PrivilegeHint {
        binary: binary.into(),
        capability: "CAP_NET_RAW".into(),
        why: format!(
            "`{binary}` con ICMP suele necesitar CAP_NET_RAW (como ping). En Ubuntu el default es `tracepath` (UDP) y casi siempre anda sin root: Señal lo intenta primero."
        ),
        commands: vec!["tracepath -n <destino>".into()],
        polkit_note: "Si traceroute pide raw y tracepath existe, Señal usa tracepath solo.".into(),
    }
}

fn journal_hint() -> PrivilegeHint {
    PrivilegeHint {
        binary: "journalctl".into(),
        capability: "systemd-journal (grupo)".into(),
        why: "El journal de systemd-resolved es del sistema. Tu usuario, por defecto, no lo lee; por eso no aparecen consultas DNS desde el arranque. No es CAP_NET_ADMIN: es el ACL del journal. Sin ese grupo, Señal no puede reconstruir dominios desde el boot.".into(),
        commands: vec![
            "# esto cambia el grupo de TU usuario (lo tenés que hacer vos; Señal no lo ejecuta):".into(),
            "sudo usermod -aG systemd-journal \"$USER\"".into(),
            "# cerrá sesión y volvé a entrar, después, solo lectura:".into(),
            "journalctl -u systemd-resolved -b --no-pager".into(),
        ],
        polkit_note: "Mientras tanto, Señal acumula programas que hablen con :53/:853 durante esta sesión.".into(),
    }
}

fn resolvectl_hint() -> PrivilegeHint {
    PrivilegeHint {
        binary: "resolvectl".into(),
        capability: "systemd-resolved".into(),
        why: "`resolvectl monitor` a veces exige estar en el grupo systemd-journal o más privilegios. Sin eso no hay DNS en vivo mientras Señal está abierta. Señal no corre como root y no va a relanzar el monitor con sudo.".into(),
        commands: vec![
            "# diagnóstico de solo lectura, en una terminal tuya:".into(),
            "resolvectl monitor".into(),
            "resolvectl show-cache".into(),
        ],
        polkit_note: "Si falla sin root, la pestaña lo dice. El historial de esta sesión (sockets a :53) igual se acumula.".into(),
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

    #[test]
    fn netfilter_hints_never_recommend_setcap() {
        for bin in ["nft", "conntrack", "iptables", "iptables-save"] {
            let h = privilege_hint(bin, "CAP_NET_ADMIN");
            for c in &h.commands {
                assert!(
                    !c.to_ascii_lowercase().contains("setcap"),
                    "{bin} sugiere setcap: {c}"
                );
                assert!(
                    !c.to_ascii_lowercase().contains("cap_net_admin+ep"),
                    "{bin} sugiere cap_net_admin: {c}"
                );
            }
            assert!(
                h.commands
                    .iter()
                    .any(|c| c.contains("sudo ") && !c.contains("setcap")),
                "{bin} debería sugerir un sudo de solo lectura"
            );
        }
        let nft = privilege_hint("nft", "CAP_NET_ADMIN");
        assert!(nft.commands.iter().any(|c| c == "sudo nft list ruleset"));
        let ct = privilege_hint("conntrack", "CAP_NET_ADMIN");
        assert!(ct.commands.iter().any(|c| c == "sudo conntrack -L"));
    }
}
