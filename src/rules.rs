use std::net::IpAddr;
use log::debug;
use ipnetwork::IpNetwork;

use crate::config::{FirewallRule, Action, Direction, Protocol};
use crate::firewall::Packet;

#[derive(Clone)]
pub struct RuleEngine {
    rules: Vec<FirewallRule>,
}

impl RuleEngine {
    pub fn new(rules: Vec<FirewallRule>) -> Self {
        Self { rules }
    }
    
    pub fn apply_rules(&self, packet: &Packet) -> Option<Action> {
        // Only process enabled rules
        for rule in self.rules.iter().filter(|r| r.enabled) {
            if self.rule_matches(rule, packet) {
                debug!("Rule '{}' matched for packet", rule.name);
                return Some(rule.action.clone());
            }
        }
        
        None
    }
    
    fn rule_matches(&self, rule: &FirewallRule, packet: &Packet) -> bool {
        // Check direction
        match rule.direction {
            Direction::Outbound => {
                if !packet.is_outbound() {
                    return false;
                }
            },
            Direction::Inbound => {
                if !packet.is_inbound() {
                    return false;
                }
            },
            Direction::Any => {
            }
        }

        // Check protocol
        match rule.protocol {
            Protocol::TCP => {
                if packet.protocol != Protocol::TCP {
                    return false;
                }
            },
            Protocol::UDP => {
                if packet.protocol != Protocol::UDP {
                    return false;
                }
            },
            Protocol::ICMP => {
                if packet.protocol != Protocol::ICMP {
                    return false;
                }
            },
            Protocol::Any => {
                // Any protocol is acceptable
            }
        }
