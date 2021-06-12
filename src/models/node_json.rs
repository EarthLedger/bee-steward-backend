use crate::config::CONFIG;
use crate::errors::ApiError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;

/// We have two kinds of clusters:
/// 1. based on computers
/// 2. based on customers (remap)

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Cheque {
    beneficiary: String,
    chequebook: String,
    payout: u128,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PeerInfo {
    peer: String,
    lastreceived: Option<Cheque>,
    lastsent: Option<Cheque>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NodeInfo {
    id: String,
    cheques: Vec<PeerInfo>,
    peers: u32,
    address: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ClusterStatus {
    time: String,
    node_count: u32,
    cheque_count: u32,
    updates: Vec<NodeInfo>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CustomerClusterInfo {
    name: String,
    server_id: String,
    node_start: u32,
    node_end: u32,
}

type ClusterConfig = HashMap<String, CustomerClusterInfo>;

// TODO: change to use db
pub fn get_cluster_config() -> ClusterConfig {
    let file =
        File::open(&CONFIG.cluster_config_file).expect("cluster config should open correctly");
    serde_json::from_reader(file).expect("Cluster config JSON file parse fail")
}

pub fn load_by_customer_cluster(customer_id: &str) -> Result<ClusterStatus, ApiError> {
    let cluster_config = get_cluster_config();
    let customer = cluster_config
        .get(customer_id)
        .ok_or(ApiError::NotFound("not found customer config".to_string()))?;
    let cluster_path = format!("{}/{}.json", CONFIG.nodes_status_path, customer.server_id);
    let nodes_status_file = File::open(&cluster_path)
        .map_err(|_e| ApiError::NotFound("not found customer nodes".to_string()))?;
    let nodes_status: ClusterStatus = serde_json::from_reader(nodes_status_file)
        .map_err(|e| ApiError::ParseError(e.to_string()))?;

    let mut result = ClusterStatus {
        time: nodes_status.time.clone(),
        node_count: 0,
        cheque_count: 0,
        updates: vec![],
    };

    // go through nodes filter out belongs to customer
    for update in &nodes_status.updates {
        let id: u32 = update.id.parse().unwrap();
        if id >= customer.node_start && id <= customer.node_end {
            result.node_count += 1;
            result.updates.push(update.clone());
        }
    }

    Ok(result)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn load_cluster_config() {
        let config = get_cluster_config();
        for (customer_id, cluster_info) in &config {
            println!("{}: \"{:?}\"", customer_id, cluster_info);
        }
    }

    #[test]
    fn load_customer_cluster() {
        let result = load_by_customer_cluster("635362904".into());
        println!(
            "load result: {:?}",
            serde_json::to_string(&result.unwrap()).unwrap()
        );
    }
}
