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
];
const BIN_DIRS: &[&str] = &["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

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

pub fn resolve_bin(name: &str) -> Result<PathBuf> {
    if !ALLOWED_BINS.contains(&name) {
        return Err(CoreError::CommandNotAllowed(name.to_string()));
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
    let bin = resolve_bin(name)?;
    let mut cmd = Command::new(&bin);
    cmd.args(args.iter().map(OsStr::new));
    cmd.env_clear();
    cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    cmd.env("LC_ALL", "C");
    cmd.env("LANG", "C");

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
    let bin = resolve_bin(name)?;
    let mut cmd = Command::new(&bin);
    cmd.args(args.iter().map(OsStr::new));
    cmd.env_clear();
    cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    cmd.env("LC_ALL", "C");
    cmd.env("LANG", "C");

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
pub fn spawn_allowed(name: &str, args: &[&str]) -> Result<std::process::Child> {
    let bin = resolve_bin(name)?;
    let mut cmd = Command::new(&bin);
    cmd.args(args.iter().map(OsStr::new));
    cmd.env_clear();
    cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    cmd.env("LC_ALL", "C");
    cmd.env("LANG", "C");
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd.spawn().map_err(|e| CoreError::CommandFailed {
        comando: name.to_string(),
        detalle: e.to_string(),
    })
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
