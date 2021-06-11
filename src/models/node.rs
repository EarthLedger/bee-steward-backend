use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Cheque {
    beneficiary: String,
    chequebook: String,
    payout: u128,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PeerInfo {
    peer: String,
    lastreceived: Cheque,
    lastsent: Cheque,
}

#[derive(Debug, Deserialize, Serialize)]
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
