use std::time::Duration;

use crate::p2p::{NetworkNode, NodeCommand};

pub mod p2p;
pub mod zk;

#[tokio::main]

pub async fn main() {
    let mut node = NetworkNode::new(9000);
    let mut node_2 = NetworkNode::new(9001);

    let node_2_peer_id = *node_2.swarm.local_peer_id();
    // Wait for nodes to start listening
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Subscribe to topics BEFORE spawning
    node.subscribe_to_topic("zkproof").await.unwrap();
    node_2.subscribe_to_topic("zkproof").await.unwrap();

    let node_command_sender = node.get_command_sender();
    let node_2_command_sender = node_2.get_command_sender();

    // Now spawn the run loops
    tokio::spawn(async move {
        node.run().await.unwrap();
    });
    tokio::spawn(async move {
        node_2.run().await.unwrap();
    });

    tokio::time::sleep(Duration::from_secs(10)).await;

    println!("Connecting nodes...");
    let node_2_addr = format!("/ip4/127.0.0.1/tcp/9001/p2p/{}", node_2_peer_id);
    node_command_sender
        .send(NodeCommand::ConnectToPeer(node_2_addr))
        .unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;

    println!("Sending messages...");
    node_command_sender
        .send(NodeCommand::SendMessage(
            "test".to_string(),
            "Hello from node 1!".to_string(),
        ))
        .unwrap();

    // Keep main alive
    tokio::signal::ctrl_c().await.unwrap();
}
