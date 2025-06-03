use anyhow::{Result, anyhow};
use log::{info, debug, warn, error};
use pnet::datalink::{self, NetworkInterface, Channel};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::Packet as PnetPacket;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Instant, Duration};

use crate::config::{AppConfig, Direction, Protocol, Action, FirewallRule};
use crate::rules::RuleEngine;
use crate::logger::Logger;
use crate::simple_geo::SimpleGeoFirewall;

pub struct Packet {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    pub direction: Direction,
    pub size: usize,
    pub timestamp: u64,
}

impl Packet {
    pub fn new(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        protocol: Protocol,
        direction: Direction,
        size: usize,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            direction,
            size,
            timestamp,
        }
    }
    
    pub fn is_outbound(&self) -> bool {
        self.direction == Direction::Outbound
    }
    
    pub fn is_inbound(&self) -> bool {
        self.direction == Direction::Inbound
    }
}

pub struct Blocker {
    enabled: bool,
    blocked_ips: HashMap<IpAddr, (Instant, Option<Duration>)>,
    whitelist: HashSet<IpAddr>,
    connection_attempts: HashMap<IpAddr, u32>,
    auto_block_threshold: u32,
    block_duration: u64,
}

impl Blocker {
    pub fn new(config: &crate::config::BlocklistConfig) -> Self {
        let mut whitelist = HashSet::new();
        for ip_str in &config.whitelist {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                whitelist.insert(ip);
            }
        }
        
        Self {
            enabled: config.enabled,
            blocked_ips: HashMap::new(),
            whitelist,
            connection_attempts: HashMap::new(),
            auto_block_threshold: config.auto_block_threshold,
            block_duration: config.block_duration,
        }
    }
    
    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        if !self.enabled || self.whitelist.contains(ip) {
            return false;
        }
        
        if let Some((timestamp, duration)) = self.blocked_ips.get(ip) {
            match duration {
                Some(d) => timestamp.elapsed() < *d,
                None => true, // Permanent block
            }
        } else {
            false
        }
    }
    
    pub fn record_connection_attempt(&mut self, ip: IpAddr) {
        if !self.enabled || self.whitelist.contains(&ip) || self.is_blocked(&ip) {
            return;
        }
        
        let count = self.connection_attempts.entry(ip).or_insert(0);
        *count += 1;
        
        if *count >= self.auto_block_threshold {
            let duration = Duration::from_secs(self.block_duration);
            self.blocked_ips.insert(ip, (Instant::now(), Some(duration)));
            self.connection_attempts.remove(&ip);
            info!("Auto-blocked IP {} for excessive connection attempts", ip);
        }
    }
    
    pub fn block_ip(&mut self, ip: IpAddr, duration: Option<u64>) -> Result<()> {
        if self.whitelist.contains(&ip) {
            return Err(anyhow!("Cannot block whitelisted IP"));
        }
        
        let duration = duration.map(Duration::from_secs);
        self.blocked_ips.insert(ip, (Instant::now(), duration));
        info!("Blocked IP {}", ip);
        Ok(())
    }
    
    pub fn unblock_ip(&mut self, ip: IpAddr) -> Result<()> {
        if self.blocked_ips.remove(&ip).is_some() {
            info!("Unblocked IP {}", ip);
            Ok(())
        } else {
            Err(anyhow!("IP not in blocklist"))
        }
    }
    
    pub fn cleanup_expired_blocks(&mut self) {
        self.blocked_ips.retain(|_, (timestamp, duration)| {
            match duration {
                Some(d) => timestamp.elapsed() < *d,
                None => true, // Keep permanent blocks
            }
        });
    }
}

pub struct Firewall {
    config: AppConfig,
    rule_engine: RuleEngine,
    logger: Logger,
    blocker: Blocker,
    geo_firewall: SimpleGeoFirewall,
    running: bool,
    handle: Option<JoinHandle<()>>,
}

impl Firewall {
    pub fn new(config: AppConfig) -> Result<Self> {
        let rule_engine = RuleEngine::new(config.rules.clone());
        let logger = Logger::new();
        let blocker = Blocker::new(&config.blocklist);
        let geo_firewall = SimpleGeoFirewall::new(
            config.geo_firewall.blocked_countries.clone(),
            config.geo_firewall.enabled
        );
        
        Ok(Self {
            config,
            rule_engine,
            logger,
            blocker,
            geo_firewall,
            running: false,
            handle: None,
        })
    }
    
    pub fn run(&mut self) -> Result<()> {
        if self.running {
            return Err(anyhow!("Firewall already running"));
        }
        
        self.running = true;
        info!("Starting firewall");
        
        let interface = if self.config.general.interface == "default" {
            // Get default interface
            datalink::interfaces()
                .into_iter()
                .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
                .ok_or_else(|| anyhow!("No suitable network interface found"))?
        } else {
            // Find specific interface
            datalink::interfaces()
                .into_iter()
                .find(|iface| iface.name == self.config.general.interface)
                .ok_or_else(|| anyhow!("Interface not found"))?
        };
        
        info!("Using network interface: {}", interface.name);
        
        // Ajout des nouvelles lignes de log ici
        info!("Interface selection: {}", interface.name);
        info!("Interface MAC: {:?}", interface.mac);
        info!("Interface IPs: {:?}", interface.ips);
        
        // Log geo-firewall status
        if self.config.geo_firewall.enabled {
            info!("🌍 Geo-firewall enabled. Blocked countries: {:?}", self.config.geo_firewall.blocked_countries);
        } else {
            info!("🌍 Geo-firewall disabled");
        }
        
        // Create a channel to receive on
        let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(anyhow!("Unsupported channel type")),
            Err(e) => return Err(anyhow!("Unable to create channel: {}", e)),
        };
        
        let config = self.config.clone();
        let rules = self.rule_engine.clone();
        let logger_clone = self.logger.clone();
        let blocker = Arc::new(Mutex::new(self.blocker.clone()));
        let geo_firewall = Arc::new(Mutex::new(self.geo_firewall.clone()));
        
        let handle = thread::spawn(move || {
            let local_mac = interface.mac;
            
            while let Ok(packet_data) = rx.next() {
                if let Some(eth_packet) = EthernetPacket::new(packet_data) {
                    // Determine packet direction
                    let direction = if let Some(mac) = local_mac {
                        if eth_packet.get_source() == mac {
                            Direction::Outbound
                        } else if eth_packet.get_destination() == mac {
                            Direction::Inbound
                        } else {
                            Direction::Any
                        }
                    } else {
                        Direction::Any
                    };
                    
                    // Process the packet based on its type
                    match eth_packet.get_ethertype() {
                        EtherTypes::Ipv4 => {
                            if let Some(ipv4_packet) = Ipv4Packet::new(eth_packet.payload()) {
                                Self::process_ipv4_packet(&ipv4_packet, direction, &config, &rules, &logger_clone, &blocker, &geo_firewall);
                            }
                        },
                        EtherTypes::Ipv6 => {
                            if let Some(ipv6_packet) = Ipv6Packet::new(eth_packet.payload()) {
                                Self::process_ipv6_packet(&ipv6_packet, direction, &config, &rules, &logger_clone, &blocker, &geo_firewall);
                            }
                        },
                        _ => { /* Ignore other packet types */ }
                    }
                }
            }
        });
        
        self.handle = Some(handle);
        
        // Start cleanup thread for expired blocks
        let blocker_cleanup = Arc::new(Mutex::new(self.blocker.clone()));
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(60));
                let mut blocker = blocker_cleanup.lock().unwrap();
                blocker.cleanup_expired_blocks();
            }
        });
        
        Ok(())
    }
    
    fn process_ipv4_packet(
        ipv4_packet: &Ipv4Packet,
        direction: Direction,
        config: &AppConfig,
        rules: &RuleEngine,
        logger: &Logger,
        blocker: &Arc<Mutex<Blocker>>,
        geo_firewall: &Arc<Mutex<SimpleGeoFirewall>>,
    ) {
        let src_ip = IpAddr::V4(ipv4_packet.get_source());
        let dst_ip = IpAddr::V4(ipv4_packet.get_destination());
        let size = ipv4_packet.payload().len();
        
        // Check geo-firewall first
        {
            let geo_fw = geo_firewall.lock().unwrap();
            if direction == Direction::Inbound && geo_fw.should_block(src_ip) {
                logger.log_blocked_packet(src_ip, dst_ip, None, None, Protocol::Any, direction, size);
                return;
            }
            if direction == Direction::Outbound && geo_fw.should_block(dst_ip) {
                logger.log_blocked_packet(src_ip, dst_ip, None, None, Protocol::Any, direction, size);
                return;
            }
        }
        
        // Check if IP is blocked
        {
            let blocker = blocker.lock().unwrap();
            if blocker.is_blocked(&src_ip) || blocker.is_blocked(&dst_ip) {
                logger.log_blocked_packet(src_ip, dst_ip, None, None, Protocol::Any, direction, size);
                return;
            }
        }
        
        match ipv4_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                    let packet = Packet::new(
                        src_ip,
                        dst_ip,
                        Some(tcp_packet.get_source()),
                        Some(tcp_packet.get_destination()),
                        Protocol::TCP,
                        direction,
                        size,
                    );
                    
                    Self::handle_packet(&packet, config, rules, logger, blocker);
                }
            },
            IpNextHeaderProtocols::Udp => {
                if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload()) {
                    let packet = Packet::new(
                        src_ip,
                        dst_ip,
                        Some(udp_packet.get_source()),
                        Some(udp_packet.get_destination()),
                        Protocol::UDP,
                        direction,
                        size,
                    );
                    
                    Self::handle_packet(&packet, config, rules, logger, blocker);
                }
            },
            IpNextHeaderProtocols::Icmp => {
                if let Some(_) = IcmpPacket::new(ipv4_packet.payload()) {
                    let packet = Packet::new(
                        src_ip,
                        dst_ip,
                        None,
                        None,
                        Protocol::ICMP,
                        direction,
                        size,
                    );
                    
                    Self::handle_packet(&packet, config, rules, logger, blocker);
                }
            },
            _ => {
                let packet = Packet::new(
                    src_ip,
                    dst_ip,
                    None,
                    None,
                    Protocol::Any,
                    direction,
                    size,
                );
                
                Self::handle_packet(&packet, config, rules, logger, blocker);
            }
        }
    }
    
    fn process_ipv6_packet(
        ipv6_packet: &Ipv6Packet,
        direction: Direction,
        config: &AppConfig,
        rules: &RuleEngine,
        logger: &Logger,
        blocker: &Arc<Mutex<Blocker>>,
        geo_firewall: &Arc<Mutex<SimpleGeoFirewall>>,
    ) {
        let src_ip = IpAddr::V6(ipv6_packet.get_source());
        let dst_ip = IpAddr::V6(ipv6_packet.get_destination());
        let size = ipv6_packet.payload().len();
        
        // Check geo-firewall first
        {
            let geo_fw = geo_firewall.lock().unwrap();
            if direction == Direction::Inbound && geo_fw.should_block(src_ip) {
                logger.log_blocked_packet(src_ip, dst_ip, None, None, Protocol::Any, direction, size);
                return;
            }
            if direction == Direction::Outbound && geo_fw.should_block(dst_ip) {
                logger.log_blocked_packet(src_ip, dst_ip, None, None, Protocol::Any, direction, size);
                return;
            }
        }
        
        // Similar to process_ipv4_packet but for IPv6
        // Check if IP is blocked
        {
            let blocker = blocker.lock().unwrap();
            if blocker.is_blocked(&src_ip) || blocker.is_blocked(&dst_ip) {
                logger.log_blocked_packet(src_ip, dst_ip, None, None, Protocol::Any, direction, size);
                return;
            }
        }
        
        // Process IPv6 packet similarly to IPv4
        let packet = Packet::new(
            src_ip,
            dst_ip,
            None,
            None,
            Protocol::Any,
            direction,
            size,
        );
        
        Self::handle_packet(&packet, config, rules, logger, blocker);
    }
    
    fn handle_packet(
        packet: &Packet,
        config: &AppConfig,
        rules: &RuleEngine,
        logger: &Logger,
        blocker: &Arc<Mutex<Blocker>>,
    ) {
        // Apply rules
        match rules.apply_rules(packet) {
            Some(action) => {
                match action {
                    Action::Allow => {
                        logger.log_allowed_packet(
                            packet.src_ip, packet.dst_ip, packet.src_port, 
                            packet.dst_port, packet.protocol.clone(), packet.direction.clone(), packet.size
                        );
                    },
                    Action::Block => {
                        logger.log_blocked_packet(
                            packet.src_ip, packet.dst_ip, packet.src_port, 
                            packet.dst_port, packet.protocol.clone(), packet.direction.clone(), packet.size
                        );
                        
                        // Record connection attempt for potential auto-blocking
                        let mut blocker = blocker.lock().unwrap();
                        blocker.record_connection_attempt(packet.src_ip);
                    },
                    Action::Log => {
                        logger.log_packet(
                            packet.src_ip, packet.dst_ip, packet.src_port, 
                            packet.dst_port, packet.protocol.clone(), packet.direction.clone(), packet.size
                        );
                    },
                }
            },
            None => {
                // Apply default action
                match config.general.default_action {
                    Action::Allow => {
                        logger.log_allowed_packet(
                            packet.src_ip, packet.dst_ip, packet.src_port, 
                            packet.dst_port, packet.protocol.clone(), packet.direction.clone(), packet.size
                        );
                    },
                    Action::Block => {
                        logger.log_blocked_packet(
                            packet.src_ip, packet.dst_ip, packet.src_port, 
                            packet.dst_port, packet.protocol.clone(), packet.direction.clone(), packet.size
                        );
                        
                        // Record connection attempt
                        let mut blocker = blocker.lock().unwrap();
                        blocker.record_connection_attempt(packet.src_ip);
                    },
                    Action::Log => {
                        logger.log_packet(
                            packet.src_ip, packet.dst_ip, packet.src_port, 
                            packet.dst_port, packet.protocol.clone(), packet.direction.clone(), packet.size
                        );
                    },
                }
            }
        }
    }
    
    pub fn stop(&mut self) -> Result<()> {
        if !self.running {
            return Err(anyhow!("Firewall not running"));
        }
        
        if let Some(handle) = self.handle.take() {
            // Let the thread end naturally or wait a bit and force it
            // This is simplified - in a full implementation, we would use a proper exit signal
            handle.join().ok();
        }
        
        self.running = false;
        info!("Firewall stopped");
        
        Ok(())
    }
    
    pub fn is_running(&self) -> bool {
        self.running
    }
    
    pub fn update_rules(&mut self, rules: Vec<FirewallRule>) {
        self.config.rules = rules.clone();
        self.rule_engine = RuleEngine::new(rules);
        info!("Firewall rules updated");
    }
    
    pub fn add_to_blacklist(&mut self, ip: IpAddr, duration: Option<u64>) -> Result<()> {
        self.blocker.block_ip(ip, duration)
    }
    
    pub fn remove_from_blacklist(&mut self, ip: IpAddr) -> Result<()> {
        self.blocker.unblock_ip(ip)
    }
    
    pub fn block_country(&mut self, country_code: &str) {
        self.geo_firewall.block_country(country_code);
        info!("Blocked country: {}", country_code);
    }
    
    pub fn enable_threat_protection(&mut self) {
        self.geo_firewall.enable_threat_protection();
        info!("Threat protection enabled");
    }
}

// Add clone implementations for required types
impl Clone for Blocker {
    fn clone(&self) -> Self {
        Self {
            enabled: self.enabled,
            blocked_ips: self.blocked_ips.clone(),
            whitelist: self.whitelist.clone(),
            connection_attempts: self.connection_attempts.clone(),
            auto_block_threshold: self.auto_block_threshold,
            block_duration: self.block_duration,
        }
    }
}
