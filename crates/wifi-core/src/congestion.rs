use crate::types::{Band, ChannelBar, NearbyNetwork};

/// En 2.4 GHz un AP de 20 MHz en el canal C solapa C±4.
pub fn overlaps_24(center: u32, other: u32) -> bool {
    center.abs_diff(other) < 5
}

pub fn congestion_bars(nearby: &[NearbyNetwork]) -> Vec<ChannelBar> {
    let mut bars = Vec::new();

    for channel in 1u32..=13 {
        let mut count = 0u32;
        let mut overlap = 0u32;
        let mut strongest = None::<u8>;
        for n in nearby.iter().filter(|n| n.band == Some(Band::Ghz24)) {
            let Some(ch) = n.channel else { continue };
            if ch == channel {
                count += 1;
                strongest = Some(strongest.unwrap_or(0).max(n.signal_pct.unwrap_or(0)));
            } else if overlaps_24(channel, ch) {
                overlap += 1;
            }
        }
        if count > 0 || overlap > 0 {
            bars.push(ChannelBar {
                channel,
                band: Band::Ghz24,
                count,
                overlap,
                strongest_pct: strongest,
            });
        }
    }

    for band in [Band::Ghz5, Band::Ghz6] {
        let mut channels: Vec<u32> = nearby
            .iter()
            .filter(|n| n.band == Some(band))
            .filter_map(|n| n.channel)
            .collect();
        channels.sort_unstable();
        channels.dedup();
        for channel in channels {
            let nets: Vec<&NearbyNetwork> = nearby
                .iter()
                .filter(|n| n.band == Some(band) && n.channel == Some(channel))
                .collect();
            let strongest = nets.iter().filter_map(|n| n.signal_pct).max();
            bars.push(ChannelBar {
                channel,
                band,
                count: nets.len() as u32,
                overlap: 0,
                strongest_pct: strongest,
            });
        }
    }
    bars
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(ch: u32, band: Band, pct: u8) -> NearbyNetwork {
        NearbyNetwork {
            in_use: false,
            ssid: format!("n{ch}"),
            bssid: format!("aa:bb:cc:dd:ee:{ch:02x}"),
            channel: Some(ch),
            frequency_mhz: None,
            band: Some(band),
            signal_dbm: None,
            signal_pct: Some(pct),
            security: "WPA2".into(),
            rate: None,
        }
    }

    #[test]
    fn channel_1_overlaps_up_to_5() {
        assert!(overlaps_24(1, 5));
        assert!(!overlaps_24(1, 6));
        assert!(!overlaps_24(6, 11));
        assert!(overlaps_24(6, 10));
    }

    #[test]
    fn congestion_counts_overlap_on_24() {
        let nearby = vec![
            net(1, Band::Ghz24, 80),
            net(5, Band::Ghz24, 40),
            net(36, Band::Ghz5, 70),
        ];
        let bars = congestion_bars(&nearby);
        let ch1 = bars
            .iter()
            .find(|b| b.channel == 1 && b.band == Band::Ghz24)
            .unwrap();
        assert_eq!(ch1.count, 1);
        assert!(ch1.overlap >= 1);
        let ch36 = bars
            .iter()
            .find(|b| b.channel == 36 && b.band == Band::Ghz5)
            .unwrap();
        assert_eq!(ch36.count, 1);
        assert_eq!(ch36.overlap, 0);
    }
}
