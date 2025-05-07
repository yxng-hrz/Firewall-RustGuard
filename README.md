RustGuard
A minimalist user-mode application firewall written in Rust that filters outgoing connections based on customizable rules. Features a logging system for tracking suspicious connection attempts and dynamic blocking of specific IPs or ports.
Features

User-Mode Firewall: No kernel modules or system-level modifications required
Outgoing Connection Filtering: Control which applications can access the network
Rule-Based Filtering: Define custom rules to allow or block connections
Comprehensive Logging: Track all connection attempts, with detailed information
Dynamic IP/Port Blocking: Automatically block suspicious IP addresses or ports
Low Resource Usage: Minimal memory and CPU footprint
IPv4 and IPv6 Support: Full support for both IPv4 and IPv6

Installation
Prerequisites

Rust and Cargo (1.70.0 or newer)
Linux-based OS (for packet capture functionality)
Administrator privileges (for network packet capture)

Building from Source
bash# Clone the repository
git clone https://github.com/yourusername/rustguard.git
cd rustguard

# Build the project
cargo build --release

# The binary will be available at target/release/rustguard
Usage
bash# Run with default settings
sudo ./target/release/rustguard

# Run with a custom configuration file
sudo ./target/release/rustguard -c my_config.toml

# Run in verbose mode for debugging
sudo ./target/release/rustguard -v

# Specify a custom log file
sudo ./target/release/rustguard -l rustguard_custom.log
Command Line Options

-c, --config-file <FILE>: Path to configuration file (default: config/default.toml)
-l, --log-file <FILE>: Path to log file (default: rustguard.log)
-v, --verbose: Enable verbose logging
-f, --foreground: Run in foreground (don't daemonize)
-h, --help: Show help information
-V, --version: Show version information

Configuration
RustGuard uses a TOML configuration file. The default configuration is included in config/default.toml. You can modify this file or create your own.
Configuration Example
toml# RustGuard Configuration

[general]
interface = "default"  # Use "default" for system's default interface
default_action = "block"  # What to do when no rule matches
enable_ipv6 = true

# Define your firewall rules here
[[rules]]
name = "Allow HTTP"
action = "allow"
direction = "outbound"
protocol = "tcp"
dst_port = 80
enabled = true

[[rules]]
name = "Allow HTTPS"
action = "allow"
direction = "outbound"
protocol = "tcp"
dst_port = 443
enabled = true

[logging]
level = "info"
file = "rustguard.log"
max_size = 10  # Maximum log file size in MB
rotation_count = 5  # Number of rotated log files to keep

[blacklist]
enabled = true
auto_block_threshold = 5  # Block after this many connection attempts
block_duration = 3600  # Block duration in seconds (1 hour)
whitelist = ["127.0.0.1", "::1"]  # Always allow these IPs
Firewall Rules
RustGuard uses a rule-based system to decide which connections to allow or block:

Name: A descriptive name for the rule
Action: What to do with matching packets (allow, block, log)
Direction: Packet direction (outbound, inbound, any)
Protocol: Network protocol (tcp, udp, icmp, any)
Source IP: Source IP address or CIDR network
Destination IP: Destination IP address or CIDR network
Source Port: Source port number
Destination Port: Destination port number
Enabled: Whether the rule is active

Rules are evaluated in order, and the first matching rule determines the action.
Logging
RustGuard logs all connection attempts, including:

Timestamp
Source and destination IP addresses
Source and destination ports
Protocol
Packet size
Action taken (allowed, blocked, logged)

Logs are stored in the specified log file and are automatically rotated when they reach the configured size.
Dynamic Blocking
RustGuard can automatically block IP addresses that exhibit suspicious behavior:

Excessive connection attempts
Port scanning
Failed login attempts

Blocked IPs are temporarily added to the blacklist for the configured duration.
License
This project is licensed under the MIT License - see the LICENSE file for details.
Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

Fork the repository
Create your feature branch (git checkout -b feature/amazing-feature)
Commit your changes (git commit -m 'Add some amazing feature')
Push to the branch (git push origin feature/amazing-feature)
Open a Pull Request
