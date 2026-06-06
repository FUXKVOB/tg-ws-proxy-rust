use std::sync::LazyLock;
use std::sync::RwLock;
use rand::seq::{IndexedRandom, SliceRandom};

pub struct Balancer {
    domains: Vec<String>,
    dc_to_domain: std::collections::HashMap<u32, String>,
}

impl Default for Balancer {
    fn default() -> Self {
        Self::new()
    }
}

impl Balancer {
    pub fn new() -> Self {
        Self {
            domains: Vec::new(),
            dc_to_domain: std::collections::HashMap::new(),
        }
    }

    pub fn update_domains_list(&mut self, domains: &[String]) {
        self.domains = domains.to_vec();
        self.dc_to_domain.clear();
        for dc_id in [1u32, 2, 3, 4, 5, 203] {
            if let Some(domain) = self.domains.choose(&mut rand::rng()) {
                self.dc_to_domain.insert(dc_id, domain.clone());
            }
        }
    }

    pub fn update_domain_for_dc(&mut self, dc_id: u32, domain: &str) -> bool {
        if self.dc_to_domain.get(&dc_id).map(|s| s.as_str()) == Some(domain) {
            return false;
        }
        self.dc_to_domain.insert(dc_id, domain.to_string());
        true
    }

    pub fn get_domains_for_dc(&self, dc_id: u32) -> Vec<String> {
        let mut result = Vec::new();
        if let Some(current) = self.dc_to_domain.get(&dc_id) {
            result.push(current.clone());
        }
        let mut shuffled = self.domains.clone();
        shuffled.shuffle(&mut rand::rng());
        for domain in &shuffled {
            if !result.iter().any(|d| d == domain) {
                result.push(domain.clone());
            }
        }
        result
    }
}

pub static BALANCER: LazyLock<RwLock<Balancer>> = LazyLock::new(|| RwLock::new(Balancer::new()));
