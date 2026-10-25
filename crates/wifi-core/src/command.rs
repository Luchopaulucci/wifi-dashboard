use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::error::{CoreError, Result};

const ALLOWED_BINS: &[&str] = &[
    "nmcli",
    "iw",
    "ip",
    "ping",
    "avahi-resolve-address",
    "ss",
    "conntrack",
    "nft",
    "iptables",
    "iptables-save",
    "traceroute",
    "traceroute6",
    "tracepath",
    "tracepath6",
    "resolvectl",
    "journalctl",
    "pkexec",
];
const BIN_DIRS: &[&str] = &["/usr/bin", "/bin", "/usr/sbin", "/sbin"];
/// pkexec necesita el bus de sesión y el display para el diálogo de polkit.
/// El resto del entorno sigue limpio (PATH fijo, LC_ALL=C).
const PKEXEC_ENV_KEEP: &[&str] = &[
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_SESSION_TYPE",
    "XDG_CURRENT_DESKTOP",
];

/// Slot de argv: o un literal exacto, o un valor ya validado (iface/host/ipv4).
#[derive(Clone, Copy, Debug)]
enum ArgPat {
    Exact(&'static str),
    Iface,
    Host,
    Ipv4,
}

struct AllowedSpec {
    bin: &'static str,
    args: &'static [ArgPat],
}

const ALLOWED_COMMANDS: &[AllowedSpec] = &[
    AllowedSpec {
        bin: "nmcli",
        args: &[
            ArgPat::Exact("-t"),
            ArgPat::Exact("-f"),
            ArgPat::Exact("DEVICE,TYPE,STATE"),
            ArgPat::Exact("device"),
            ArgPat::Exact("status"),
        ],
    },
    AllowedSpec {
        bin: "nmcli",
        args: &[
            ArgPat::Exact("-t"),
            ArgPat::Exact("device"),
            ArgPat::Exact("show"),
        ],
    },
    AllowedSpec {
        bin: "nmcli",
        args: &[
            ArgPat::Exact("-t"),
            ArgPat::Exact("device"),
            ArgPat::Exact("show"),
            ArgPat::Iface,
        ],
    },
    AllowedSpec {
        bin: "nmcli",
        args: &[
            ArgPat::Exact("-t"),
            ArgPat::Exact("-f"),
            ArgPat::Exact("IN-USE,BSSID,SSID,CHAN,FREQ,RATE,SIGNAL,SECURITY"),
            ArgPat::Exact("device"),
            ArgPat::Exact("wifi"),
            ArgPat::Exact("list"),
        ],
    },
    AllowedSpec {
        bin: "nmcli",
        args: &[
            ArgPat::Exact("device"),
            ArgPat::Exact("wifi"),
            ArgPat::Exact("rescan"),
        ],
    },
    AllowedSpec {
        bin: "iw",
        args: &[ArgPat::Exact("dev")],
    },
    AllowedSpec {
        bin: "iw",
        args: &[ArgPat::Exact("dev"), ArgPat::Iface, ArgPat::Exact("link")],
    },
    AllowedSpec {
        bin: "iw",
        args: &[ArgPat::Exact("dev"), ArgPat::Iface, ArgPat::Exact("info")],
    },
    AllowedSpec {
        bin: "ip",
        args: &[
            ArgPat::Exact("-4"),
            ArgPat::Exact("route"),
            ArgPat::Exact("show"),
            ArgPat::Exact("default"),
        ],
    },
    AllowedSpec {
        bin: "ip",
        args: &[
            ArgPat::Exact("route"),
            ArgPat::Exact("show"),
            ArgPat::Exact("default"),
        ],
    },
    AllowedSpec {
        bin: "ip",
        args: &[
            ArgPat::Exact("-4"),
            ArgPat::Exact("-o"),
            ArgPat::Exact("addr"),
            ArgPat::Exact("show"),
        ],
    },
    AllowedSpec {
        bin: "ip",
        args: &[
            ArgPat::Exact("-4"),
            ArgPat::Exact("-o"),
            ArgPat::Exact("addr"),
            ArgPat::Exact("show"),
            ArgPat::Exact("dev"),
            ArgPat::Iface,
        ],
    },
    AllowedSpec {
        bin: "ip",
        args: &[ArgPat::Exact("neigh"), ArgPat::Exact("show")],
    },
    AllowedSpec {
        bin: "ping",
        args: &[
            ArgPat::Exact("-c"),
            ArgPat::Exact("1"),
            ArgPat::Exact("-n"),
            ArgPat::Exact("-W"),
            ArgPat::Exact("1"),
            ArgPat::Ipv4,
        ],
    },
    AllowedSpec {
        bin: "avahi-resolve-address",
        args: &[ArgPat::Ipv4],
    },
    AllowedSpec {
        bin: "ss",
        args: &[ArgPat::Exact("-H"), ArgPat::Exact("-tunap")],
    },
    AllowedSpec {
        bin: "ss",
        args: &[ArgPat::Exact("-tunap")],
    },
    AllowedSpec {
        bin: "ss",
        args: &[ArgPat::Exact("-H"), ArgPat::Exact("-tulpn")],
    },
    AllowedSpec {
        bin: "ss",
        args: &[ArgPat::Exact("-tulpn")],
    },
    AllowedSpec {
        bin: "conntrack",
        args: &[ArgPat::Exact("-L")],
    },
    AllowedSpec {
        bin: "nft",
        args: &[ArgPat::Exact("list"), ArgPat::Exact("ruleset")],
    },
    AllowedSpec {
        bin: "iptables-save",
        args: &[ArgPat::Exact("-c")],
    },
    AllowedSpec {
        bin: "iptables",
        args: &[ArgPat::Exact("-S")],
    },
    AllowedSpec {
        bin: "resolvectl",
        args: &[ArgPat::Exact("statistics")],
    },
    AllowedSpec {
        bin: "resolvectl",
        args: &[ArgPat::Exact("show-cache")],
    },
    AllowedSpec {
        bin: "resolvectl",
        args: &[ArgPat::Exact("monitor")],
    },
    AllowedSpec {
        bin: "journalctl",
        args: &[
            ArgPat::Exact("-u"),
            ArgPat::Exact("systemd-resolved"),
            ArgPat::Exact("-b"),
            ArgPat::Exact("--no-pager"),
            ArgPat::Exact("-o"),
            ArgPat::Exact("cat"),
            ArgPat::Exact("-n"),
            ArgPat::Exact("4000"),
        ],
    },
    AllowedSpec {
        bin: "traceroute",
        args: &[
            ArgPat::Exact("-n"),
            ArgPat::Exact("-q"),
            ArgPat::Exact("1"),
            ArgPat::Exact("-w"),
            ArgPat::Exact("2"),
            ArgPat::Exact("--"),
            ArgPat::Host,
        ],
    },
    AllowedSpec {
        bin: "traceroute",
        args: &[
            ArgPat::Exact("-6"),
            ArgPat::Exact("-n"),
            ArgPat::Exact("-q"),
            ArgPat::Exact("1"),
            ArgPat::Exact("-w"),
            ArgPat::Exact("2"),
            ArgPat::Exact("--"),
            ArgPat::Host,
        ],
    },
    AllowedSpec {
        bin: "traceroute6",
        args: &[
            ArgPat::Exact("-n"),
            ArgPat::Exact("-q"),
            ArgPat::Exact("1"),
            ArgPat::Exact("-w"),
            ArgPat::Exact("2"),
            ArgPat::Exact("--"),
            ArgPat::Host,
        ],
    },
    AllowedSpec {
        bin: "tracepath",
        args: &[ArgPat::Exact("-n"), ArgPat::Exact("--"), ArgPat::Host],
    },
    AllowedSpec {
        bin: "tracepath",
        args: &[
            ArgPat::Exact("-6"),
            ArgPat::Exact("-n"),
            ArgPat::Exact("--"),
            ArgPat::Host,
        ],
    },
    AllowedSpec {
        bin: "tracepath6",
        args: &[ArgPat::Exact("-n"), ArgPat::Exact("--"), ArgPat::Host],
    },
];

impl AllowedSpec {
    fn matches(&self, name: &str, args: &[&str]) -> bool {
        if self.bin != name || self.args.len() != args.len() {
            return false;
        }
        self.args
            .iter()
            .zip(args.iter())
            .all(|(pat, got)| match pat {
                ArgPat::Exact(s) => *got == *s,
                ArgPat::Iface => validate_iface(got).is_ok(),
                ArgPat::Host => validate_host(got).is_ok(),
                ArgPat::Ipv4 => validate_ipv4(got).is_ok(),
            })
    }
}

/// Allowlist por binario **y** argv exacto (slots validados aparte).
pub fn args_are_allowed(name: &str, args: &[&str]) -> bool {
    if name == "pkexec" {
        return pkexec_inner_allowed(args);
    }
    ALLOWED_COMMANDS.iter().any(|spec| spec.matches(name, args))
}

/// `pkexec <ruta allowlisted> <args fijos del binario interno>`.
/// El interno tiene que pasar la misma allowlist de argv; no hay pkexec anidado.
fn pkexec_inner_allowed(args: &[&str]) -> bool {
    let Some((target, rest)) = args.split_first() else {
        return false;
    };
    let path = Path::new(target);
    let Some(bin) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    if bin == "pkexec" || !ALLOWED_BINS.contains(&bin) {
        return false;
    }
    if !BIN_DIRS.iter().any(|d| Path::new(d).join(bin) == path) {
        return false;
    }
    ALLOWED_COMMANDS.iter().any(|spec| spec.matches(bin, rest))
}

fn ensure_args_allowed(name: &str, args: &[&str]) -> Result<()> {
    if args_are_allowed(name, args) {
        Ok(())
    } else {
        Err(CoreError::CommandNotAllowed(format!(
            "{name} {}",
            args.join(" ")
        )))
    }
}

#[derive(Debug, Clone)]
pub struct CmdOutput {
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
    pub code: Option<i32>,
}

impl CmdOutput {
    pub fn combined(&self) -> String {
        let mut s = String::new();
        if !self.stderr.is_empty() {
            s.push_str(&self.stderr);
        }
        if !self.stdout.is_empty() {
            if !s.is_empty() {
                s.push('\n');
            }
            s.push_str(&self.stdout);
        }
        s
    }
}

pub fn validate_iface(name: &str) -> Result<&str> {
    let ok = (1..=16).contains(&name.len())
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(name)
    } else {
        Err(CoreError::InvalidArg(format!("interfaz: {name}")))
    }
}

pub fn validate_ipv4(ip: &str) -> Result<&str> {
    if ip.parse::<std::net::Ipv4Addr>().is_ok() {
        Ok(ip)
    } else {
        Err(CoreError::InvalidArg(format!("ipv4: {ip}")))
    }
}

/// Destino para traceroute/tracepath: IPv4, IPv6 o hostname ASCII.
/// Nunca se pasa a un shell; igual rechazamos metacaracteres y flags (`-n`).
pub fn validate_host(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let host_port = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .trim();
    if host_port.is_empty() || host_port.len() > 253 {
        return Err(CoreError::InvalidArg(format!("destino: {raw}")));
    }
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        rest.split(']').next().unwrap_or("").to_string()
    } else if host_port.matches(':').count() == 1
        && host_port
            .split(':')
            .next()
            .is_some_and(|h| h.parse::<std::net::Ipv4Addr>().is_ok())
    {
        host_port.split(':').next().unwrap_or("").to_string()
    } else {
        host_port.to_string()
    };
    let host = host.trim();
    if host.is_empty() || host.starts_with('-') {
        return Err(CoreError::InvalidArg(format!("destino: {raw}")));
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(host.to_string());
    }
    let ok = host.split('.').all(|label| {
        let b = label.as_bytes();
        (1..=63).contains(&b.len())
            && b[0].is_ascii_alphanumeric()
            && b[b.len() - 1].is_ascii_alphanumeric()
            && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
    }) && host.is_ascii();
    if ok {
        Ok(host.trim_end_matches('.').to_string())
    } else {
        Err(CoreError::InvalidArg(format!("destino: {raw}")))
    }
}

fn prepare_command(name: &str, args: &[&str]) -> Result<Command> {
    let bin = resolve_bin(name)?;
    let mut cmd = Command::new(&bin);
    cmd.args(args.iter().map(OsStr::new));
    cmd.env_clear();
    cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    cmd.env("LC_ALL", "C");
    cmd.env("LANG", "C");
    if name == "pkexec" {
        for key in PKEXEC_ENV_KEEP {
            if let Some(val) = std::env::var_os(key) {
                cmd.env(key, val);
            }
        }
    }
    Ok(cmd)
}

pub fn resolve_bin(name: &str) -> Result<PathBuf> {
    if !ALLOWED_BINS.contains(&name) {
        return Err(CoreError::CommandNotAllowed(name.to_string()));
    }
    #[cfg(test)]
    if test_runner::is_hidden(name) {
        return Err(CoreError::BinaryMissing(name.to_string()));
    }
    #[cfg(test)]
    if let Some(path) = test_runner::resolve_override(name) {
        return Ok(path);
    }
    for dir in BIN_DIRS {
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(CoreError::BinaryMissing(name.to_string()))
}

pub fn bin_exists(name: &str) -> bool {
    resolve_bin(name).is_ok()
}

/// Ejecuta un binario de la lista permitida con argumentos ya validados.
/// Nunca usa shell ni interpola strings.
pub fn run_cmd(name: &str, args: &[&str]) -> Result<String> {
    run_cmd_timeout(name, args, Duration::from_secs(8))
}

pub fn run_cmd_timeout(name: &str, args: &[&str], timeout: Duration) -> Result<String> {
    ensure_args_allowed(name, args)?;
    let mut cmd = prepare_command(name, args)?;

    let output = if timeout.as_millis() == 0 {
        cmd.output()
    } else {
        // std::process no tiene timeout nativo; usamos el timeout del propio comando
        // (ping -W / -w) y un tope razonable acá vía spawn+try_wait.
        wait_with_timeout(&mut cmd, timeout)
    }
    .map_err(|e| CoreError::CommandFailed {
        comando: name.to_string(),
        detalle: e.to_string(),
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(CoreError::CommandFailed {
            comando: name.to_string(),
            detalle: format!("{} {}", stderr.trim(), stdout.trim()),
        });
    }
    String::from_utf8(output.stdout).map_err(|e| CoreError::Parse(e.to_string()))
}

/// Como `run_cmd`, pero no falla por código de salida ≠ 0 (sirve para
/// detectar "permission denied" vs reglas vacías vs traceroute con hops *).
pub fn run_cmd_capture(name: &str, args: &[&str], timeout: Duration) -> Result<CmdOutput> {
    ensure_args_allowed(name, args)?;
    #[cfg(test)]
    if let Some(out) = test_runner::capture_override(name, args) {
        return Ok(out);
    }
    let mut cmd = prepare_command(name, args)?;

    let output = wait_with_timeout(&mut cmd, timeout).map_err(|e| CoreError::CommandFailed {
        comando: name.to_string(),
        detalle: e.to_string(),
    })?;

    Ok(CmdOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        success: output.status.success(),
        code: output.status.code(),
    })
}

/// Lanza un binario permitido con stdout/stderr en pipe. El caller drena.
/// `timeout` en cero = sin watchdog (p.ej. `resolvectl monitor`). Si no, un
/// hilo mata el proceso al vencerse el tiempo.
pub fn spawn_allowed(name: &str, args: &[&str], timeout: Duration) -> Result<std::process::Child> {
    ensure_args_allowed(name, args)?;
    #[cfg(test)]
    if let Some(child) = test_runner::spawn_override(name, args) {
        return child;
    }
    let mut cmd = prepare_command(name, args)?;
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let child = cmd.spawn().map_err(|e| CoreError::CommandFailed {
        comando: name.to_string(),
        detalle: e.to_string(),
    })?;
    if !timeout.is_zero() {
        watchdog_kill(child.id(), timeout);
    }
    Ok(child)
}

/// Mata el PID que spawneamos (p.ej. `pkexec`). No alcanza al hijo root de
/// pkexec: un usuario sin privilegios no le puede mandar señal.
fn watchdog_kill(pid: u32, timeout: Duration) {
    std::thread::spawn(move || {
        std::thread::sleep(timeout);
        for path in ["/bin/kill", "/usr/bin/kill"] {
            if Path::new(path).is_file() {
                let _ = Command::new(path).args(["-9", &pid.to_string()]).status();
                return;
            }
        }
    });
}

fn wait_with_timeout(
    cmd: &mut Command,
    timeout: Duration,
) -> std::io::Result<std::process::Output> {
    use std::io::Read;
    use std::thread;
    use std::time::Instant;

    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    let mut stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("stdout no disponible"))?;
    let mut stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("stderr no disponible"))?;

    let stdout_handle = thread::spawn(move || {
        let mut buf = Vec::new();
        stdout_pipe.read_to_end(&mut buf).map(|_n| buf)
    });
    let stderr_handle = thread::spawn(move || {
        let mut buf = Vec::new();
        stderr_pipe.read_to_end(&mut buf).map(|_n| buf)
    });

    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_handle.join();
            let _ = stderr_handle.join();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "tiempo de espera agotado",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    };

    let stdout = stdout_handle
        .join()
        .map_err(|_| std::io::Error::other("falló el hilo de stdout"))??;
    let stderr = stderr_handle
        .join()
        .map_err(|_| std::io::Error::other("falló el hilo de stderr"))??;

    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

/// Runner inyectable solo en tests: no spawnea pkexec real.
#[cfg(test)]
pub mod test_runner {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::process::Command;

    thread_local! {
        static ENABLED: RefCell<bool> = const { RefCell::new(false) };
        static RESOLVE: RefCell<HashMap<String, PathBuf>> = RefCell::new(HashMap::new());
        static HIDDEN: RefCell<std::collections::HashSet<String>> =
            RefCell::new(std::collections::HashSet::new());
        static REPLY: RefCell<Option<CmdOutput>> = const { RefCell::new(None) };
        static ARGV: RefCell<Vec<Vec<String>>> = const { RefCell::new(Vec::new()) };
        static SLOW_STDERR: RefCell<Option<u64>> = const { RefCell::new(None) };
    }

    pub struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            ENABLED.with(|e| *e.borrow_mut() = false);
            RESOLVE.with(|m| m.borrow_mut().clear());
            HIDDEN.with(|h| h.borrow_mut().clear());
            REPLY.with(|r| *r.borrow_mut() = None);
            ARGV.with(|a| a.borrow_mut().clear());
            SLOW_STDERR.with(|s| *s.borrow_mut() = None);
        }
    }

    pub fn install() -> Guard {
        ENABLED.with(|e| *e.borrow_mut() = true);
        Guard
    }

    pub fn set_bin(name: &str, path: &str) {
        RESOLVE.with(|m| {
            m.borrow_mut().insert(name.to_string(), PathBuf::from(path));
        });
    }

    pub fn hide_bin(name: &str) {
        HIDDEN.with(|h| {
            h.borrow_mut().insert(name.to_string());
        });
    }

    pub(super) fn is_hidden(name: &str) -> bool {
        ENABLED.with(|e| *e.borrow()) && HIDDEN.with(|h| h.borrow().contains(name))
    }

    pub fn set_capture_ok(stdout: &str) {
        REPLY.with(|r| {
            *r.borrow_mut() = Some(CmdOutput {
                stdout: stdout.to_string(),
                stderr: String::new(),
                success: true,
                code: Some(0),
            });
        });
    }

    pub fn take_argv() -> Vec<Vec<String>> {
        ARGV.with(|a| std::mem::take(&mut *a.borrow_mut()))
    }

    /// Child que imprime un hop y deja stderr abierto `hold_secs` (nieto).
    /// Matar al padre no cierra stderr: sirve para probar que cancel no hace join.
    pub fn set_spawn_slow_stderr(hold_secs: u64) {
        SLOW_STDERR.with(|s| *s.borrow_mut() = Some(hold_secs));
    }

    pub(super) fn spawn_override(name: &str, args: &[&str]) -> Option<Result<std::process::Child>> {
        if !ENABLED.with(|e| *e.borrow()) {
            return None;
        }
        let hold = SLOW_STDERR.with(|s| *s.borrow())?;
        if name != "pkexec" {
            return None;
        }
        let pkexec = resolve_override("pkexec").unwrap_or_else(|| PathBuf::from("/usr/bin/pkexec"));
        let mut argv = vec![pkexec.to_string_lossy().into_owned()];
        argv.extend(args.iter().map(|s| (*s).to_string()));
        ARGV.with(|a| a.borrow_mut().push(argv));
        let script = format!("printf ' 1  1.1.1.1  1.000 ms\\n'; sleep {hold} >&2 & exec sleep 30");
        Some(
            Command::new("/bin/sh")
                .arg("-c")
                .arg(script)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| CoreError::CommandFailed {
                    comando: name.to_string(),
                    detalle: e.to_string(),
                }),
        )
    }

    pub(super) fn resolve_override(name: &str) -> Option<PathBuf> {
        if !ENABLED.with(|e| *e.borrow()) {
            return None;
        }
        RESOLVE.with(|m| m.borrow().get(name).cloned())
    }

    pub(super) fn capture_override(name: &str, args: &[&str]) -> Option<CmdOutput> {
        if !ENABLED.with(|e| *e.borrow()) {
            return None;
        }
        if name != "pkexec" {
            return None;
        }
        let pkexec = resolve_override("pkexec").unwrap_or_else(|| PathBuf::from("/usr/bin/pkexec"));
        let mut argv = vec![pkexec.to_string_lossy().into_owned()];
        argv.extend(args.iter().map(|s| (*s).to_string()));
        ARGV.with(|a| a.borrow_mut().push(argv));
        Some(REPLY.with(|r| {
            r.borrow().clone().unwrap_or(CmdOutput {
                stdout: String::new(),
                stderr: String::new(),
                success: true,
                code: Some(0),
            })
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iface_ok() {
        assert!(validate_iface("wlan0").is_ok());
        assert!(validate_iface("wlp2s0").is_ok());
        assert!(validate_iface("wlx001122334455").is_ok());
    }

    #[test]
    fn iface_rejects_injection() {
        assert!(validate_iface("wlan0;rm -rf /").is_err());
        assert!(validate_iface("wlan0 && id").is_err());
        assert!(validate_iface("../etc").is_err());
        assert!(validate_iface("").is_err());
        assert!(validate_iface("wlan0$(id)").is_err());
        assert!(validate_iface("wlan0\nssid").is_err());
    }

    #[test]
    fn ipv4_ok_and_rejects_injection() {
        assert!(validate_ipv4("192.168.0.1").is_ok());
        assert!(validate_ipv4("1.1.1.1").is_ok());
        assert!(validate_ipv4("8.8.8.8; id").is_err());
        assert!(validate_ipv4("1.1.1.1 && reboot").is_err());
        assert!(validate_ipv4("256.0.0.1").is_err());
        assert!(validate_ipv4("").is_err());
    }

    #[test]
    fn host_ok_and_rejects_injection() {
        assert_eq!(validate_host("8.8.8.8").unwrap(), "8.8.8.8");
        assert_eq!(
            validate_host("https://one.one.one.one/path").unwrap(),
            "one.one.one.one"
        );
        assert_eq!(
            validate_host("2001:4860:4860::8888").unwrap(),
            "2001:4860:4860::8888"
        );
        assert_eq!(
            validate_host("[2001:4860:4860::8888]").unwrap(),
            "2001:4860:4860::8888"
        );
        assert!(validate_host("fibertel.com.ar").is_ok());
        assert!(validate_host("-n").is_err());
        assert!(validate_host("8.8.8.8; id").is_err());
        assert!(validate_host("example.com && reboot").is_err());
        assert!(validate_host("foo$(id).com").is_err());
        assert!(validate_host("").is_err());
        assert!(validate_host("a b.com").is_err());
    }

    #[test]
    fn new_bins_are_allowed_not_shell() {
        assert!(matches!(
            resolve_bin("ss"),
            Ok(_) | Err(CoreError::BinaryMissing(_))
        ));
        assert!(matches!(
            resolve_bin("nft"),
            Ok(_) | Err(CoreError::BinaryMissing(_))
        ));
        assert!(matches!(
            resolve_bin("pkexec"),
            Ok(_) | Err(CoreError::BinaryMissing(_))
        ));
        assert!(matches!(
            resolve_bin("bash"),
            Err(CoreError::CommandNotAllowed(_))
        ));
    }

    #[test]
    fn unknown_bin_rejected() {
        assert!(matches!(
            resolve_bin("bash"),
            Err(CoreError::CommandNotAllowed(_))
        ));
        assert!(matches!(
            resolve_bin("sh"),
            Err(CoreError::CommandNotAllowed(_))
        ));
    }

    #[test]
    fn argv_must_match_exactly() {
        assert!(args_are_allowed("nft", &["list", "ruleset"]));
        assert!(args_are_allowed("ss", &["-H", "-tulpn"]));
        assert!(args_are_allowed("conntrack", &["-L"]));
        assert!(args_are_allowed("tracepath", &["-n", "--", "1.1.1.1"]));
        assert!(args_are_allowed(
            "journalctl",
            &[
                "-u",
                "systemd-resolved",
                "-b",
                "--no-pager",
                "-o",
                "cat",
                "-n",
                "4000"
            ]
        ));
        assert!(!args_are_allowed("nft", &["flush", "ruleset"]));
        assert!(!args_are_allowed("nft", &["list"]));
        assert!(!args_are_allowed("ss", &["-tunap", "-a"]));
        assert!(!args_are_allowed("conntrack", &["-D"]));
        assert!(!args_are_allowed("iptables", &["-F"]));
        assert!(!args_are_allowed("bash", &["-c", "id"]));
        assert!(!args_are_allowed("tracepath", &["-n", "--", "-n"]));
        assert!(ensure_args_allowed("nft", &["flush", "ruleset"]).is_err());
        assert!(args_are_allowed(
            "pkexec",
            &["/usr/sbin/nft", "list", "ruleset"]
        ));
        assert!(!args_are_allowed(
            "pkexec",
            &["/usr/sbin/nft", "flush", "ruleset"]
        ));
        assert!(!args_are_allowed("pkexec", &["/usr/bin/bash", "-c", "id"]));
        assert!(!args_are_allowed(
            "pkexec",
            &["/tmp/nft", "list", "ruleset"]
        ));
    }

    #[test]
    fn large_stdout_finishes_quickly() {
        use std::time::Instant;

        let mut cmd = Command::new("/usr/bin/head");
        cmd.args(["-c", "262144", "/dev/zero"]);
        let start = Instant::now();
        let output = wait_with_timeout(&mut cmd, Duration::from_secs(3))
            .expect("la salida grande no debería trabar el pipe");
        assert!(output.status.success());
        assert!(
            output.stdout.len() > 200_000,
            "stdout={} bytes",
            output.stdout.len()
        );
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "tardó {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn timeout_kills_long_process() {
        use std::time::Instant;

        let mut cmd = Command::new("/usr/bin/sleep");
        cmd.arg("30");
        let start = Instant::now();
        let err = wait_with_timeout(&mut cmd, Duration::from_millis(250))
            .expect_err("sleep 30 debería cortarse por timeout");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "el kill no fue a tiempo: {:?}",
            start.elapsed()
        );
    }
}
