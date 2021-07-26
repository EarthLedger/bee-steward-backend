use crate::config::CONFIG;
use crate::database::{init_pool, MysqlPool};
use crate::errors::ApiError;
use crate::models::node::{update_node_info, UpdateNodeInfo};
use crate::models::node_info::{create_node_info, NewNodeInfo};
use diesel::mysql::MysqlConnection;
use num::bigint::BigInt;
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::sync::Mutex;
use walkdir::WalkDir;

/// We have two kinds of clusters:
/// 1. based on computers
/// 2. based on customers (remap)

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct Cheque {
    beneficiary: String,
    chequebook: String,
    payout: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct PeerInfo {
    peer: String,
    lastreceived: Option<Cheque>,
    lastsent: Option<Cheque>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct PeerBalance {
    peer: String,
    balance: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct Settlement {
    peer: String,
    received: String,
    sent: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct NodeInfo {
    pub id: String,
    pub cheques: Vec<PeerInfo>,
    pub peers: u32,
    pub address: String,
    pub depth: u32,
    pub balances: Vec<PeerBalance>,
    pub node_xbzz: String,
    pub node_xdai: String,
    pub chequebook_xbzz: String,
    pub chequebook_address: String,
    //pub settlements: Vec<Settlement>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ClusterStatus {
    time: String,
    node_count: u32,
    cheque_count: u32,
    pub updates: Vec<NodeInfo>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CustomerClusterInfo {
    name: String,
    server_id: String,
    node_start: u32,
    node_end: u32,
}

type ClusterConfig = HashMap<String, CustomerClusterInfo>;

// Global node status hash map
lazy_static! {
    #[derive(Debug)]
    static ref G_NODE_MAP: Mutex<HashMap<String, NodeInfo>> = {
        let map = HashMap::new();
        Mutex::new(map)
    };

    static ref G_DB_POOL: MysqlPool = init_pool::<MysqlConnection>(CONFIG.clone()).unwrap();
}

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

pub fn load_by_server_cluster(server_id: &str) -> Result<ClusterStatus, ApiError> {
    let cluster_path = format!(
        "{}/{}.json",
        CONFIG.nodes_status_path,
        server_id.to_string()
    );
    let nodes_status_file = File::open(&cluster_path)
        .map_err(|_e| ApiError::NotFound("not found customer nodes".to_string()))?;
    let nodes_status: ClusterStatus = serde_json::from_reader(nodes_status_file)
        .map_err(|e| ApiError::ParseError(e.to_string()))?;

    Ok(nodes_status)
}

pub fn get_node_info(addr: &str) -> Result<NodeInfo, ApiError> {
    match G_NODE_MAP.lock().unwrap().get(addr) {
        Some(info) => Ok(info.clone()),
        None => Err(ApiError::NotFound("not found node status".to_string())),
    }
}

// Timer task auto load node status json and build up node addr hash map
pub fn update_node_status() -> Result<(), ApiError> {
    println!("update node status");
    {
        //println!("node status: {:?}", g_node_map.lock().unwrap());
    }

    // go through dir
    for entry in WalkDir::new(CONFIG.nodes_status_path.clone())
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let f_name = entry.file_name().to_string_lossy();
        println!("file name:{}", f_name);
        if f_name.ends_with(".json") {
            let nodes_status_file =
                File::open(format!("{}{}", CONFIG.nodes_status_path, f_name))
                    .map_err(|_e| ApiError::NotFound("not found customer nodes".to_string()))?;
            match serde_json::from_reader::<_, ClusterStatus>(nodes_status_file) {
                Ok(nodes_status) => {
                    //println!("status: {:?}", nodes_status);
                    // go through json to update node status
                    let mut map = G_NODE_MAP.lock().unwrap();
                    for node in nodes_status.updates {
                        update_db(&node);
                        map.insert(node.address.clone(), node);
                    }

                    // add to db
                }
                Err(e) => println!("error: {:?}", e),
            }
        }
    }

    Ok(())
}

fn update_db(node: &NodeInfo) {
    let mut db_node = UpdateNodeInfo {
        addr: node.address.clone(),
        cheque_book_addr: Some(node.chequebook_address.clone()),
        run_status: 1,
        connection: node.peers as i32,
        depth: node.depth as i32,
        cheque_received_count: 0,
        cheque_received_balance: "0".to_string(),
        peer_max_postive_balance: "0".to_string(),
        node_bzz: node.node_xbzz.clone(),
        node_xdai: node.node_xdai.clone(),
        cheque_bzz: node.chequebook_xbzz.clone(),
    };

    // handle cheque count and total balance
    let mut total_cheque_received_balance: BigInt = Zero::zero();
    for cheque in &node.cheques {
        match &cheque.lastreceived {
            Some(item) => {
                println!("payout:{}", item.payout);
                //let payout = BigUint::from_bytes_le(item.payout.as_bytes());
                let payout = item.payout.parse::<BigInt>().unwrap();
                total_cheque_received_balance += payout;
                db_node.cheque_received_count += 1;
            }
            None => {}
        }
    }
    db_node.cheque_received_balance = total_cheque_received_balance.to_string();

    if node.balances.len() > 0 {
        db_node.peer_max_postive_balance = node.balances[0].balance.clone();
    }

    let _ = update_node_info(&G_DB_POOL, &db_node);
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
