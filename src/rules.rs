use std::net::IpAddr;
use log::debug;
use ipnetwork::IpNetwork;

use crate::config::{FirewallRule, Action, Direction, Protocol};
use crate::TestPacket;

#[derive(Clone)]
pub struct RuleEngine {
    rules: Vec<FirewallRule>,
}

impl RuleEngine {
    pub fn new(rules: Vec<FirewallRule>) -> Self {
        Self { rules }
    }
    
    pub fn apply_rules(&self, packet: &TestPacket) -> Option<Action> {
        for rule in self.rules.iter().filter(|r| r.enabled) {
            if self.rule_matches(rule, packet) {
                debug!("Rule '{}' matched for packet", rule.name);
                return Some(rule.action.clone());
            }
        }
        None
    }
    
    fn rule_matches(&self, rule: &FirewallRule, packet: &TestPacket) -> bool {
        // Direction
        match rule.direction {
            Direction::Outbound => if !packet.is_outbound() { return false; },
            Direction::Inbound => if !packet.is_inbound() { return false; },
            Direction::Any => {},
        }

        // Protocol
        match rule.protocol {
            Protocol::TCP => if packet.protocol != Protocol::TCP { return false; },
            Protocol::UDP => if packet.protocol != Protocol::UDP { return false; },
            Protocol::ICMP => if packet.protocol != Protocol::ICMP { return false; },
            Protocol::Any => {},
        }

        // Source IP
        if let Some(ref src_ip_str) = rule.src_ip {
            if !self.ip_matches(src_ip_str, packet.src_ip) { return false; }
        }
        
        // Destination IP
        if let Some(ref dst_ip_str) = rule.dst_ip {
            if !self.ip_matches(dst_ip_str, packet.dst_ip) { return false; }
        }
        
        // Source port
        if let Some(src_port) = rule.src_port {
            if let Some(packet_src_port) = packet.src_port {
                if src_port != packet_src_port { return false; }
            } else {
                return false;
            }
        }
        
        // Destination port
        if let Some(dst_port) = rule.dst_port {
            if let Some(packet_dst_port) = packet.dst_port {
                if dst_port != packet_dst_port { return false; }
            } else {
                return false;
            }
        }
        
        true
    }
    
    fn ip_matches(&self, ip_rule: &str, packet_ip: IpAddr) -> bool {
        if let Ok(network) = ip_rule.parse::<IpNetwork>() {
            return network.contains(packet_ip);
        }
        
        if let Ok(rule_ip) = ip_rule.parse::<IpAddr>() {
            return rule_ip == packet_ip;
        }
        
        debug!("Invalid IP or CIDR in rule: {}", ip_rule);
        false
    }
}
