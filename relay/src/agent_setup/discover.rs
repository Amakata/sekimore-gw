//! Step 0: find the gateway and point this container at it.
//!
//! Docker's internal DNS (127.0.0.11) is switched off in the dev container, so the gateway is
//! the host on the subnet with port 53 open. The shell script pinged, read the ARP cache and
//! scanned in bash; a parallel TCP connect over the /24 does the same in under a second.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{bail, Context};

pub struct Iface {
    pub ip: Ipv4Addr,
    pub prefix: u8,
}

/// eth0's address and prefix from `ip -4 -o addr show eth0` (`… inet 10.200.6.3/24 …`).
pub fn parse_iface(ip_addr_output: &str) -> Option<Iface> {
    let mut it = ip_addr_output.split_whitespace();
    while let Some(tok) = it.next() {
        if tok == "inet" {
            let cidr = it.next()?;
            let (ip, prefix) = cidr.split_once('/')?;
            return Some(Iface {
                ip: ip.parse().ok()?,
                prefix: prefix.parse().ok()?,
            });
        }
    }
    None
}

pub fn iface() -> anyhow::Result<Iface> {
    if !super::files::on_path("ip") {
        bail!("'ip' not found; install iproute2 in the dev image");
    }
    let out = super::files::run(
        std::process::Command::new("ip").args(["-4", "-o", "addr", "show", "eth0"]),
    )
    .context("ip -4 -o addr show eth0")?;
    parse_iface(&out).context("could not read eth0's address and prefix")
}

/// The addresses worth trying, our own left out: the whole /24 around us for a /24 or smaller,
/// the usual gateway addresses of the nearby /24s for a larger subnet.
pub fn candidates(me: &Iface) -> Vec<Ipv4Addr> {
    let o = me.ip.octets();
    let mut v = Vec::new();
    if me.prefix >= 24 {
        for i in 1..=254u8 {
            let c = Ipv4Addr::new(o[0], o[1], o[2], i);
            if c != me.ip {
                v.push(c);
            }
        }
    } else {
        for third in 0..=255u8 {
            for fourth in [1u8, 2, 254, 253] {
                let c = Ipv4Addr::new(o[0], o[1], third, fourth);
                if c != me.ip {
                    v.push(c);
                }
            }
        }
        // our own /24 first
        v.sort_by_key(|c| (c.octets()[2] != o[2], c.octets()));
    }
    v
}

async fn dns_open(ip: Ipv4Addr) -> bool {
    let addr = SocketAddr::new(IpAddr::V4(ip), 53);
    matches!(
        tokio::time::timeout(
            Duration::from_millis(300),
            tokio::net::TcpStream::connect(addr)
        )
        .await,
        Ok(Ok(_))
    )
}

/// The first candidate with port 53 open, three passes with a pause between them (the gateway
/// may still be coming up when postStart runs).
pub async fn scan(cands: &[Ipv4Addr]) -> Option<Ipv4Addr> {
    for attempt in 0..3 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(700)).await;
        }
        for chunk in cands.chunks(64) {
            let mut set = tokio::task::JoinSet::new();
            for ip in chunk {
                let ip = *ip;
                set.spawn(async move {
                    if dns_open(ip).await {
                        Some(ip)
                    } else {
                        None
                    }
                });
            }
            let mut found: Vec<Ipv4Addr> = Vec::new();
            while let Some(r) = set.join_next().await {
                if let Ok(Some(ip)) = r {
                    found.push(ip);
                }
            }
            // the lowest address wins when several answer, so the choice is stable
            found.sort();
            if let Some(ip) = found.into_iter().next() {
                return Some(ip);
            }
        }
    }
    None
}

pub async fn gateway() -> anyhow::Result<Ipv4Addr> {
    let me = iface()?;
    println!(
        "[agent] My IP: {}, Subnet: /{}; scanning for the gateway (port 53)",
        me.ip, me.prefix
    );
    let cands = candidates(&me);
    match scan(&cands).await {
        Some(ip) => {
            println!("[agent] sekimore-gw IP (discovered): {ip}");
            Ok(ip)
        }
        None => bail!(
            "could not find sekimore-gw: no host with port 53 open in the /{} subnet. Is the gateway container running?",
            me.prefix
        ),
    }
}

/// `/etc/resolv.conf` and the default route to the gateway. Route errors are reported, not
/// fatal, as before: a container that already routes there has nothing to change.
pub fn point_at(gw: Ipv4Addr) -> anyhow::Result<()> {
    std::fs::write("/etc/resolv.conf", format!("nameserver {gw}\n"))
        .context("write /etc/resolv.conf")?;
    println!("[agent] DNS: nameserver {gw}");
    let _ = std::process::Command::new("ip")
        .args(["route", "del", "default"])
        .output();
    match std::process::Command::new("ip")
        .args([
            "route",
            "add",
            "default",
            "via",
            &gw.to_string(),
            "dev",
            "eth0",
        ])
        .output()
    {
        Ok(o) if o.status.success() => println!("[agent] default via {gw} set"),
        Ok(o) => println!(
            "[agent] WARNING: ip route add default via {gw}: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => println!("[agent] WARNING: ip route: {e}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eth0_is_read_off_ip_addr_and_the_candidates_skip_us() {
        let me = parse_iface("2: eth0    inet 10.200.6.3/24 brd 10.200.6.255 scope global eth0\\       valid_lft forever preferred_lft forever\n").unwrap();
        assert_eq!((me.ip, me.prefix), ("10.200.6.3".parse().unwrap(), 24));
        let c = candidates(&me);
        assert_eq!(c.len(), 253);
        assert!(!c.contains(&me.ip));
        assert_eq!(c[0], "10.200.6.1".parse::<Ipv4Addr>().unwrap());
        let wide = Iface {
            ip: "10.200.6.3".parse().unwrap(),
            prefix: 16,
        };
        let c = candidates(&wide);
        assert_eq!(
            c[0],
            "10.200.6.1".parse::<Ipv4Addr>().unwrap(),
            "our own /24 first"
        );
        assert!(c.len() > 1000 && c.len() <= 1024);
        assert!(parse_iface("").is_none());
    }
}
