use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::error::{CoreError, Result};

const ALLOWED_BINS: &[&str] = &["nmcli", "iw", "ip", "ping", "avahi-resolve-address"];
const BIN_DIRS: &[&str] = &["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

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

fn wait_with_timeout(
    cmd: &mut Command,
    timeout: Duration,
) -> std::io::Result<std::process::Output> {
    use std::thread;
    use std::time::Instant;

    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let start = Instant::now();
    loop {
        if let Some(_status) = child.try_wait()? {
            return child.wait_with_output();
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "tiempo de espera agotado",
            ));
        }
        thread::sleep(Duration::from_millis(20));
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
}
