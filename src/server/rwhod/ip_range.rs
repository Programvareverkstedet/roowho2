use std::{
    fmt,
    net::{AddrParseError, IpAddr},
    num::ParseIntError,
    str::FromStr,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A range of IP addresses, written in CIDR notation (e.g. `10.0.0.0/8` or `fd00::/8`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpRange {
    addr: IpAddr,
    prefix_len: u8,
}

#[derive(Debug, thiserror::Error)]
pub enum IpRangeParseError {
    #[error("invalid IP address: {0}")]
    InvalidAddress(#[from] AddrParseError),

    #[error("invalid prefix length: {0}")]
    InvalidPrefixLength(#[from] ParseIntError),

    #[error("prefix length /{0} is too large for {1}")]
    PrefixLengthTooLarge(u8, IpAddr),
}

impl IpRange {
    /// Returns whether `ip` lies within this range.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let bits = |ip| match ip {
            IpAddr::V4(ip) => u128::from(ip.to_bits()) << 96,
            IpAddr::V6(ip) => ip.to_bits(),
        };

        let mask = u128::MAX
            .checked_shl(128 - u32::from(self.prefix_len))
            .unwrap_or(0);

        self.addr.is_ipv4() == ip.is_ipv4() && (bits(self.addr) ^ bits(ip)) & mask == 0
    }
}

impl FromStr for IpRange {
    type Err = IpRangeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, prefix_len) = s.split_once('/').map_or((s, None), |(a, p)| (a, Some(p)));
        let addr: IpAddr = addr.parse()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix_len = prefix_len.map(str::parse).transpose()?.unwrap_or(max);
        if prefix_len > max {
            return Err(IpRangeParseError::PrefixLengthTooLarge(prefix_len, addr));
        }
        Ok(Self { addr, prefix_len })
    }
}

impl fmt::Display for IpRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

impl Serialize for IpRange {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for IpRange {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(s: &str) -> IpRange {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_parse_and_display() {
        assert_eq!(range("10.0.0.0/8").to_string(), "10.0.0.0/8");
        assert_eq!(range("192.168.1.5").to_string(), "192.168.1.5/32");
        assert_eq!(range("fd00::/8").to_string(), "fd00::/8");
        assert_eq!(range("fd00::1").to_string(), "fd00::1/128");
    }

    #[test]
    fn test_parse_errors() {
        use IpRangeParseError::*;
        let parse = |s: &str| s.parse::<IpRange>().unwrap_err();
        assert!(matches!(parse("10.0.0.0/33"), PrefixLengthTooLarge(33, _)));
        assert!(matches!(parse("fd00::/129"), PrefixLengthTooLarge(129, _)));
        assert!(matches!(parse("10.0.0.0/abc"), InvalidPrefixLength(_)));
        assert!(matches!(parse("not-an-ip"), InvalidAddress(_)));
    }

    #[test]
    fn test_contains() {
        assert!(range("192.168.1.0/24").contains(ip("192.168.1.200")));
        assert!(!range("192.168.1.0/24").contains(ip("192.168.2.1")));
        assert!(range("fd00::/8").contains(ip("fd12:3456::1")));
        assert!(!range("fd00::/8").contains(ip("fe80::1")));
    }
}
