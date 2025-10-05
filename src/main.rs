// Standard library
use std::time::Duration;

// Local modules
use crate::p2p::{NetworkNode, NodeCommand};

pub mod p2p;
pub mod zk;

#[tokio::main]
pub async fn main() {
    println!("╔═══════════════════════════════════════════╗");
    println!("║   P2P Zero-Knowledge Blockchain Demo    ║");
    println!("╚═══════════════════════════════════════════╝\n");

    println!("🔧 Creating nodes...");
    let mut node = NetworkNode::new(9000);
    let mut node_2 = NetworkNode::new(9001);

    let node_2_peer_id = *node_2.swarm.local_peer_id();
    tokio::time::sleep(Duration::from_secs(1)).await;

    node.subscribe_to_topic("zkproof").await.unwrap();
    node_2.subscribe_to_topic("zkproof").await.unwrap();

    let node_command_sender = node.get_command_sender();
    let _node_2_command_sender = node_2.get_command_sender();

    println!("\n🚀 Starting node event loops...\n");
    tokio::spawn(async move {
        node.run().await.unwrap();
    });
    tokio::spawn(async move {
        node_2.run().await.unwrap();
    });

    println!("⏳ Waiting for peer discovery (10s)...\n");
    tokio::time::sleep(Duration::from_secs(10)).await;

    println!("═══════════════════════════════════════════");
    println!("🔌 Manually connecting nodes...");
    let node_2_addr = format!("/ip4/127.0.0.1/tcp/9001/p2p/{}", node_2_peer_id);
    node_command_sender
        .send(NodeCommand::ConnectToPeer(node_2_addr))
        .unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;

    println!("\n═══════════════════════════════════════════");
    println!("📨 Sending ZK-proven message from Node 1...");
    println!("═══════════════════════════════════════════");
    node_command_sender
        .send(NodeCommand::SendMessage(
            "zkproof".to_string(),
            "Hello from node 1!".to_string(),
        ))
        .unwrap();

    println!("\n💡 Press Ctrl+C to exit\n");
    tokio::signal::ctrl_c().await.unwrap();
    println!("\n👋 Shutting down...");
}
