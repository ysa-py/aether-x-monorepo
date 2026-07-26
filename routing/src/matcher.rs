//! Pure matching helpers (domain + CIDR). Stateless; tested in isolation.

use std::net::IpAddr;

use ipnet::IpNet;

use crate::rules::{DomainRule, DomainType};

/// True iff `domain` matches any of `rules`. Matching is case-insensitive.
/// For [`DomainType::Suffix`], a rule `value` matches `domain` exactly or when
/// `domain` ends with `.value` (so `google.com` matches `mail.google.com` but
/// NOT `evilgoogle.com`).
pub fn domain_matches(domain: &str, rules: &[DomainRule]) -> bool {
    let dom = domain.to_ascii_lowercase();
    rules.iter().any(|r| match r.ty {
        DomainType::Full => dom == r.value.to_ascii_lowercase(),
        DomainType::Suffix => {
            let v = r.value.to_ascii_lowercase();
            dom == v || dom.ends_with(&format!(".{v}"))
        }
        DomainType::Keyword => dom.contains(&r.value.to_ascii_lowercase()),
    })
}

/// True iff `ip` falls within any of `cidrs`.
pub fn ip_matches(ip: IpAddr, cidrs: &[IpNet]) -> bool {
    cidrs.iter().any(|c| c.contains(&ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(ty: DomainType, v: &str) -> DomainRule {
        DomainRule {
            ty,
            value: v.into(),
        }
    }

    #[test]
    fn suffix_matching() {
        let r = [rule(DomainType::Suffix, "google.com")];
        assert!(domain_matches("google.com", &r));
        assert!(domain_matches("WWW.google.com", &r)); // case-insensitive
        assert!(domain_matches("mail.google.com", &r));
        assert!(!domain_matches("evilgoogle.com", &r));
        assert!(!domain_matches("google.com.evil", &r));
    }

    #[test]
    fn full_matching() {
        let r = [rule(DomainType::Full, "Exact.IR")];
        assert!(domain_matches("exact.ir", &r));
        assert!(!domain_matches("sub.exact.ir", &r));
    }

    #[test]
    fn keyword_matching() {
        let r = [rule(DomainType::Keyword, "ads")];
        assert!(domain_matches("my.ads.example", &r));
        assert!(!domain_matches("example.com", &r));
    }

    #[test]
    fn cidr_matching() {
        let c: Vec<IpNet> = vec![
            "5.160.0.0/15".parse().unwrap(),
            "2.144.0.0/13".parse().unwrap(),
        ];
        assert!(ip_matches("5.161.2.3".parse().unwrap(), &c));
        assert!(ip_matches("2.150.1.1".parse().unwrap(), &c));
        assert!(!ip_matches("8.8.8.8".parse().unwrap(), &c));
        // IPv6 containment.
        let c6: Vec<IpNet> = vec!["2001:db8::/32".parse().unwrap()];
        assert!(ip_matches("2001:db8::1".parse().unwrap(), &c6));
        assert!(!ip_matches("2001:dead::1".parse().unwrap(), &c6));
    }
}
