//! Shared logic for pairing a wallet with a node by QR.
//!
//! Both `midwimble link` (a terminal QR) and the node's `/link` web page
//! (an on-screen QR) build the same `midwimble:node?a=…&follow=1` URI, which
//! the web wallet's scanner recognises. Keeping the construction here means
//! the two can never drift apart and emit a URI the wallet won't accept.

/// Rewrites a multiaddr's host — its leading `/ip4|ip6|dns4|dns6|dns/<value>`
/// — to `host`, choosing `ip4`/`ip6`/`dns4` by what `host` parses as, and
/// keeping the rest (`/udp/<port>/webrtc-direct/certhash/…/p2p/…`).
///
/// A node binds WebRTC on `0.0.0.0`, so its advertised listen address is not
/// dialable as-is; the operator (or the browser's own address bar) supplies
/// the host a wallet can actually reach, and this swaps it in.
pub fn rehost(addr: &str, host: &str) -> Option<String> {
    let mut parts = addr.strip_prefix('/')?.splitn(3, '/');
    let _proto = parts.next()?;
    let _value = parts.next()?;
    let rest = parts.next()?;
    let proto = if host.parse::<std::net::Ipv4Addr>().is_ok() {
        "ip4"
    } else if host.parse::<std::net::Ipv6Addr>().is_ok() {
        "ip6"
    } else {
        "dns4"
    };
    Some(format!("/{proto}/{host}/{rest}"))
}

/// The `midwimble:node?a=…&follow=1` URI for already-dialable `addrs`. With
/// `follow`, the wallet is asked to follow this node as its primary.
pub fn node_link_uri(addrs: &[String], follow: bool) -> String {
    let mut query: Vec<String> = addrs.iter().map(|a| format!("a={a}")).collect();
    if follow {
        query.push("follow=1".to_string());
    }
    format!("midwimble:node?{}", query.join("&"))
}

/// The hostname a client reached us by, from an HTTP `Host` header value:
/// strips the port, and the brackets around an IPv6 literal. `None` when the
/// value is empty.
pub fn host_from_header(host_header: &str) -> Option<String> {
    let h = host_header.trim();
    if h.is_empty() {
        return None;
    }
    if let Some(rest) = h.strip_prefix('[') {
        // [::1]:9434 -> ::1
        return rest.split(']').next().map(str::to_string);
    }
    // 192.168.1.5:9434 -> 192.168.1.5 ; a bare host stays as-is.
    Some(h.rsplit_once(':').map(|(a, _)| a).unwrap_or(h).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEMPLATE: &str =
        "/ip4/0.0.0.0/udp/9437/webrtc-direct/certhash/uEiAbc-_123/p2p/12D3KooWExample";

    #[test]
    fn rehost_swaps_ip_keeps_the_rest() {
        assert_eq!(
            rehost(TEMPLATE, "192.168.1.20").unwrap(),
            "/ip4/192.168.1.20/udp/9437/webrtc-direct/certhash/uEiAbc-_123/p2p/12D3KooWExample"
        );
    }

    #[test]
    fn rehost_picks_the_protocol_from_the_host() {
        assert!(rehost(TEMPLATE, "2001:db8::5").unwrap().starts_with("/ip6/2001:db8::5/udp/"));
        assert!(rehost(TEMPLATE, "node.local").unwrap().starts_with("/dns4/node.local/udp/"));
    }

    #[test]
    fn uri_has_addrs_and_optional_follow() {
        let a = rehost(TEMPLATE, "192.168.1.20").unwrap();
        assert_eq!(
            node_link_uri(std::slice::from_ref(&a), true),
            format!("midwimble:node?a={a}&follow=1")
        );
        assert_eq!(node_link_uri(std::slice::from_ref(&a), false), format!("midwimble:node?a={a}"));
    }

    #[test]
    fn host_header_strips_port_and_brackets() {
        assert_eq!(host_from_header("192.168.1.5:9434").as_deref(), Some("192.168.1.5"));
        assert_eq!(host_from_header("[::1]:9434").as_deref(), Some("::1"));
        assert_eq!(host_from_header("node.local").as_deref(), Some("node.local"));
        assert_eq!(host_from_header("   "), None);
    }
}
