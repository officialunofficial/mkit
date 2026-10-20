//! Destination checks for the independent pack-location connector.
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

use hyper_util::client::legacy::connect::dns::{GaiResolver, Name};
use tower_service::Service;

/// Only ordinary public unicast addresses. The explicit exclusions supplement
/// std's stable address predicates using the IANA special-purpose registries:
/// <https://www.iana.org/assignments/iana-ipv4-special-registry/>
/// <https://www.iana.org/assignments/iana-ipv6-special-registry/>
/// <https://www.iana.org/assignments/ipv6-unicast-address-assignments/>
/// IPv6 is limited to allocated global unicast, excluding transition and special-use
/// allocations even where a more specific special-purpose service is global.
const PUBLIC_V6_PREFIXES: &[(u32, u32)] = &[
    (0x2001_0200, 23),
    (0x2001_0400, 23),
    (0x2001_0600, 23),
    (0x2001_0800, 22),
    (0x2001_0c00, 23),
    (0x2001_0e00, 23),
    (0x2001_1200, 23),
    (0x2001_1400, 22),
    (0x2001_1800, 23),
    (0x2001_1a00, 23),
    (0x2001_1c00, 22),
    (0x2001_2000, 19),
    (0x2001_4000, 23),
    (0x2001_4200, 23),
    (0x2001_4400, 23),
    (0x2001_4600, 23),
    (0x2001_4800, 23),
    (0x2001_4a00, 23),
    (0x2001_4c00, 23),
    (0x2001_5000, 20),
    (0x2001_8000, 19),
    (0x2001_a000, 20),
    (0x2001_b000, 20),
    (0x2003_0000, 18),
    (0x2400_0000, 12),
    (0x2410_0000, 12),
    (0x2600_0000, 12),
    (0x2610_0000, 23),
    (0x2620_0000, 23),
    (0x2630_0000, 12),
    (0x2800_0000, 12),
    (0x2a00_0000, 12),
    (0x2a10_0000, 12),
    (0x2c00_0000, 12),
];

pub(super) fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_documentation()
                || a == 0
                || a >= 240
                || (a == 100 && (64..=127).contains(&b))
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 88 && c == 99)
                || (a == 198 && (18..=19).contains(&b)))
        }
        IpAddr::V6(ip) => {
            // Normalize both mapped and deprecated compatible IPv4 forms.
            if let Some(ip) = ip.to_ipv4() {
                return is_public(IpAddr::V4(ip));
            }
            let s = ip.segments();
            !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_unique_local()
                && !ip.is_unicast_link_local()
                && PUBLIC_V6_PREFIXES.iter().any(|&(prefix, bits)| {
                    let head = u32::from(s[0]) << 16 | u32::from(s[1]);
                    head >> (32 - bits) == prefix >> (32 - bits)
                })
                && !(s[0] == 0x2001 && s[1] == 0x0db8)
        }
    }
}

#[derive(Clone)]
pub(super) struct LocationResolver<R = GaiResolver> {
    pub(super) inner: R,
    pub(super) allow_private: bool,
}

impl<R> Service<Name> for LocationResolver<R>
where
    R: Service<Name> + Send,
    R::Response: Iterator<Item = SocketAddr>,
    R::Error: std::fmt::Display,
    R::Future: Send + 'static,
{
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let resolved = self.inner.call(name);
        let allow_private = self.allow_private;
        Box::pin(async move {
            let addresses = resolved
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            let addresses: Vec<_> = addresses
                .filter(|addr| allow_private || is_public(addr.ip()))
                .collect();
            if addresses.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "pack location has no permitted public destination",
                ));
            }
            Ok(addresses.into_iter())
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use hyper_util::client::legacy::connect::HttpConnector;
    use std::future::{Ready, ready};

    #[test]
    fn every_special_destination_range_is_rejected() {
        for address in [
            "0.1.2.3",
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.0",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.0.1",
            "172.16.0.0",
            "172.31.255.255",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.0.1",
            "198.18.0.0",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            let ip: std::net::Ipv4Addr = address.parse().unwrap();
            for ip in [
                IpAddr::V4(ip),
                IpAddr::V6(ip.to_ipv6_mapped()),
                IpAddr::V6(ip.to_ipv6_compatible()),
            ] {
                assert!(!is_public(ip), "{ip}");
            }
        }
        for address in [
            "::",
            "::1",
            "64:ff9b::a00:1",
            "64:ff9b:1::1",
            "100::1",
            "100:0:0:1::1",
            "2001::1",
            "2001:1ff::1",
            "2001:db8::1",
            "2002:7f00:1::1",
            "3ffe::1",
            "2001:1000::1",
            "2003:4000::1",
            "2d00::1",
            "3fff::1",
            "3fff:fff::1",
            "5f00::1",
            "fc00::1",
            "fdff::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "4000::1",
        ] {
            assert!(!is_public(address.parse().unwrap()), "{address}");
        }
        for address in [
            "1.1.1.1",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "198.17.255.255",
            "198.20.0.0",
            "2001:4860::8888",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
            "::8.8.8.8",
        ] {
            assert!(is_public(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn every_allocated_ipv6_prefix_is_public_except_documentation() {
        for &(prefix, bits) in PUBLIC_V6_PREFIXES {
            for head in [prefix, prefix | (u32::MAX >> bits)] {
                let ip = std::net::Ipv6Addr::from(u128::from(head) << 96 | 1);
                assert!(is_public(ip.into()), "{ip}/{bits}");
            }
        }
    }

    #[derive(Clone)]
    struct TestResolver(Vec<SocketAddr>);
    impl Service<Name> for TestResolver {
        type Response = std::vec::IntoIter<SocketAddr>;
        type Error = io::Error;
        type Future = Ready<Result<Self::Response, Self::Error>>;
        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, _: Name) -> Self::Future {
            ready(Ok(self.0.clone().into_iter()))
        }
    }

    #[test]
    fn private_dns_answers_are_rejected_before_connecting() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        for address in ["127.0.0.1", "10.0.0.1", "169.254.1.1", "::ffff:127.0.0.1"] {
            let resolver = LocationResolver {
                inner: TestResolver(vec![SocketAddr::new(address.parse().unwrap(), port)]),
                allow_private: false,
            };
            let mut connector = HttpConnector::new_with_resolver(resolver);
            let uri = format!("http://location.test:{port}/pack").parse().unwrap();
            let error = runtime.block_on(connector.call(uri)).unwrap_err();
            assert!(
                format!("{error:?}").contains("no permitted public destination"),
                "{error:?}"
            );
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
    }

    #[test]
    fn resolver_filters_mixed_answers_and_checks_each_resolution() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let public: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let private: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let mut resolver = LocationResolver {
            inner: TestResolver(vec![private, public]),
            allow_private: false,
        };
        assert_eq!(
            runtime
                .block_on(resolver.call("location.test".parse().unwrap()))
                .unwrap()
                .collect::<Vec<_>>(),
            vec![public]
        );
        resolver.inner = TestResolver(vec![private]);
        assert!(
            runtime
                .block_on(resolver.call("location.test".parse().unwrap()))
                .is_err()
        );
    }

    #[test]
    fn caller_override_allows_private_dns_connection() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let resolver = LocationResolver {
            inner: TestResolver(vec![listener.local_addr().unwrap()]),
            allow_private: true,
        };
        let mut connector = HttpConnector::new_with_resolver(resolver);
        let uri = format!(
            "http://location.test:{}/pack",
            listener.local_addr().unwrap().port()
        )
        .parse()
        .unwrap();
        runtime.block_on(connector.call(uri)).unwrap();
        listener.accept().unwrap();
    }
}
