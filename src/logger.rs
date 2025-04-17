use std::net::IpAddr;
use log::info;
use chrono::{Local, DateTime};
use std::time::UNIX_EPOCH;

use crate::config::{Direction, Protocol};

#[derive(Clone)]
pub struct Logger {}

impl Logger {
    // Crée une nouvelle instance de Logger
    pub fn new() -> Self {
        Self {}
    }
    
