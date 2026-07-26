//! Property tests for the routing engine (spec §11 fuzz coverage).

use aether_routing::{
    matcher::{domain_matches, ip_matches},
    preset,
    rules::{DomainRule, DomainType},
    Engine, Request, RuleSet,
};
use proptest::prelude::*;
use std::net::IpAddr;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn suffix_matches_real_subdomain(v in "[a-z]{1,8}", label in "[a-z0-9]{1,8}") {
        let rule = vec![DomainRule { ty: DomainType::Suffix, value: v.clone() }];
        // Build candidates outside the prop_assert! expression so the stringified
        // assertion (which is later re-formatted) contains no stray braces.
        let sub = format!("{}.{}", label, v);
        let glued = format!("{}{}", label, v);
        let bare = v.clone();
        prop_assert!(domain_matches(&sub, &rule));
        prop_assert!(!domain_matches(&glued, &rule));
        prop_assert!(domain_matches(&bare, &rule));
    }

    #[test]
    fn engine_decision_is_stable(domain in "[a-z0-9.]{1,30}", n in 0u8..) {
        let e = Engine::new(preset());
        let ip: IpAddr = format!("10.0.0.{}", n).parse().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let a = e.decide(&Request { domain: Some(&domain), ip: Some(ip) });
        let b = e.decide(&Request { domain: Some(&domain), ip: Some(ip) });
        prop_assert_eq!(a, b);
    }

    #[test]
    fn ip_match_is_set_membership(net in 1u8..=200, host in 0u8..) {
        let cidr = format!("10.{}.0.0/16", net).parse::<ipnet::IpNet>().unwrap();
        let inside: IpAddr = format!("10.{}.{}.{}", net, host % 255, host % 255).parse().unwrap();
        let outside: IpAddr = "192.168.0.1".parse().unwrap();
        prop_assert!(ip_matches(inside, &[cidr]));
        prop_assert!(!ip_matches(outside, &[cidr]));
    }
}

#[allow(dead_code)]
fn _keep(_r: RuleSet) {}
