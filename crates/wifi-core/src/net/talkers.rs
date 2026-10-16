use super::types::TalkerTag;

/// Dominios típicos de actualizaciones, telemetría, sync y "phone-home".
/// Match por sufijo (www.metrics.ubuntu.com pega en metrics.ubuntu.com).
const TALKERS: &[(&str, &str, &str)] = &[
    ("metrics.ubuntu.com", "telemetria", "Telemetría de Ubuntu"),
    (
        "popcon.ubuntu.com",
        "telemetria",
        "Popularity Contest (Ubuntu)",
    ),
    (
        "popcon.debian.org",
        "telemetria",
        "Popularity Contest (Debian)",
    ),
    (
        "daisy.ubuntu.com",
        "telemetria",
        "Whoopsie / reportes de crash de Ubuntu",
    ),
    ("errors.ubuntu.com", "telemetria", "Errores de Ubuntu"),
    (
        "api.snapcraft.io",
        "updates",
        "Snap store / actualizaciones",
    ),
    ("canonical.com", "updates", "Canonical"),
    ("archive.ubuntu.com", "updates", "Repos de Ubuntu (apt)"),
    ("security.ubuntu.com", "updates", "Security repo de Ubuntu"),
    ("ppa.launchpad.net", "updates", "PPAs de Launchpad"),
    ("packages.microsoft.com", "updates", "Repos de Microsoft"),
    ("download.docker.com", "updates", "Repos de Docker"),
    (
        "telemetry.mozilla.org",
        "telemetria",
        "Telemetría de Firefox",
    ),
    (
        "incoming.telemetry.mozilla.org",
        "telemetria",
        "Telemetría de Firefox",
    ),
    (
        "detectportal.firefox.com",
        "sync",
        "Portal cautivo de Firefox",
    ),
    (
        "firefox.settings.services.mozilla.com",
        "sync",
        "Settings de Firefox",
    ),
    (
        "location.services.mozilla.com",
        "telemetria",
        "Geo de Mozilla",
    ),
    ("crashlytics.com", "telemetria", "Crashlytics"),
    ("sentry.io", "telemetria", "Sentry"),
    ("bugsnag.com", "telemetria", "Bugsnag"),
    (
        "app-measurement.com",
        "telemetria",
        "Google Analytics / Firebase",
    ),
    ("google-analytics.com", "telemetria", "Google Analytics"),
    ("doubleclick.net", "telemetria", "DoubleClick / ads"),
    (
        "connectivitycheck.gstatic.com",
        "sync",
        "Check de conectividad de Google",
    ),
    (
        "clients3.google.com",
        "sync",
        "Check de conectividad de Google",
    ),
    ("play.googleapis.com", "updates", "Google Play APIs"),
    ("android.googleapis.com", "updates", "Android / Google APIs"),
    (
        "clientservices.googleapis.com",
        "telemetria",
        "Chrome client services",
    ),
    ("update.googleapis.com", "updates", "Updates de Google"),
    ("time.google.com", "sync", "NTP de Google"),
    ("time.cloudflare.com", "sync", "NTP de Cloudflare"),
    ("pool.ntp.org", "sync", "NTP pool"),
    ("ntp.ubuntu.com", "sync", "NTP de Ubuntu"),
    ("systemd-timesync", "sync", "timesyncd"),
    (
        "settings-win.data.microsoft.com",
        "telemetria",
        "Telemetría de Windows",
    ),
    (
        "vortex.data.microsoft.com",
        "telemetria",
        "Telemetría de Microsoft",
    ),
    (
        "watson.telemetry.microsoft.com",
        "telemetria",
        "Watson / crashes Microsoft",
    ),
    ("onedrive.live.com", "sync", "OneDrive"),
    ("icloud.com", "sync", "iCloud"),
    ("mesu.apple.com", "updates", "Updates de Apple"),
    ("ocsp.apple.com", "sync", "OCSP de Apple"),
    ("dropbox.com", "sync", "Dropbox"),
    ("notify.dropboxapi.com", "sync", "Dropbox notify"),
    ("slack.com", "sync", "Slack (sync/presencia)"),
    ("whatsapp.net", "sync", "WhatsApp"),
    ("signal.org", "sync", "Signal"),
    ("discord.gg", "sync", "Discord"),
    ("discord.com", "sync", "Discord"),
    ("steamserver.net", "updates", "Steam"),
    ("steampowered.com", "updates", "Steam"),
    ("windowsupdate.com", "updates", "Windows Update"),
    ("update.googleapis.com", "updates", "Google Update"),
    (
        "googlezip.net",
        "telemetria",
        "Chrome optimization / flywheel",
    ),
    ("safebrowsing.googleapis.com", "sync", "Safe Browsing"),
    (
        "ocsp.digicert.com",
        "sync",
        "OCSP DigiCert (chequeo de certificados)",
    ),
    ("ocsp.pki.goog", "sync", "OCSP de Google"),
    ("crl.pki.goog", "sync", "CRL de Google"),
    ("canonical-livepatch", "updates", "Livepatch de Ubuntu Pro"),
    ("livepatch.canonical.com", "updates", "Livepatch"),
    (
        "motd.ubuntu.com",
        "telemetria",
        "MOTD de Ubuntu (noticias al login)",
    ),
    (
        "cloudfront.net",
        "sync",
        "CDN CloudFront (a veces telemetría/updates)",
    ),
];

pub fn classify_talker(domain: &str) -> Option<TalkerTag> {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() {
        return None;
    }
    for (suffix, kind, label) in TALKERS {
        if domain_matches(&d, suffix) {
            return Some(TalkerTag {
                label: (*label).into(),
                kind: (*kind).into(),
            });
        }
    }
    None
}

fn domain_matches(domain: &str, suffix: &str) -> bool {
    domain == suffix || domain.ends_with(&format!(".{suffix}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_ubuntu_metrics() {
        let t = classify_talker("metrics.ubuntu.com").unwrap();
        assert_eq!(t.kind, "telemetria");
        assert!(classify_talker("foo.metrics.ubuntu.com").is_some());
        assert!(classify_talker("example.com").is_none());
    }
}
