use std::time::Duration;

use libp2p::futures::StreamExt;
use libp2p::gossipsub::{IdentTopic, MessageAuthenticity, MessageId};
use libp2p::swarm::Config;
use libp2p::{Multiaddr, Transport};
use libp2p::{
    PeerId, Swarm, gossipsub, mdns, noise,
    request_response::{self, OutboundRequestId, ProtocolSupport},
    swarm::NetworkBehaviour,
    swarm::SwarmEvent,
    tcp, yamux,
};

#[derive(NetworkBehaviour)]
struct P2PBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

pub struct NetworkNode {
    swarm: Swarm<P2PBehaviour>,
}

impl NetworkNode {
    pub fn new(local_peer_id: PeerId, port: u16) -> Self {
        let behaviour = P2PBehaviour {
            gossipsub: gossipsub::Behaviour::new(
                MessageAuthenticity::Author(local_peer_id),
                gossipsub::Config::default(),
            )
            .unwrap(),
            mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id).unwrap(),
        };

        let keypair = libp2p::identity::Keypair::generate_ed25519();

        // transport with encryption
        let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
            .upgrade(libp2p::core::upgrade::Version::V1)
            .authenticate(noise::Config::new(&keypair).unwrap())
            .multiplex(yamux::Config::default())
            .boxed();

        let mut swarm = Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            Config::with_tokio_executor()
                .with_idle_connection_timeout(Duration::from_secs(60 * 60 * 24)),
        );

        let listen_addr = format!("/ip4/0.0.0.0/tcp/{}", port);
        swarm.listen_on(listen_addr.parse().unwrap()).unwrap();
        Self { swarm }
    }

    pub async fn connect_to_peer(&mut self, addr: &str) -> Result<(), String> {
        println!("Connecting to peer: {}", addr);
        let addr: Multiaddr = addr.parse().unwrap();
        self.swarm.dial(addr).unwrap();
        Ok(())
    }

    pub async fn subscribe_to_topic(&mut self, topic_name: &str) -> Result<(), String> {
        let topic = IdentTopic::new(topic_name);
        self.swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&topic)
            .map_err(|e| format!("Failed to subscribe to topic: {}", e))?;
        println!("Subscribed to topic: {}", topic_name);
        Ok(())
    }

    pub fn send_message(&mut self, topic_name: &str, message: &str) -> Result<MessageId, String> {
        let topic = IdentTopic::new(topic_name);
        let message_id = self
            .swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic, message.as_bytes())
            .map_err(|e| format!("Failed to publish message: {}", e))?;
        println!("Sent message to topic '{}': {}", topic_name, message);
        Ok(message_id)
    }
    pub async fn run(&mut self) -> Result<(), String> {
        let mut ctrl_c = Box::pin(tokio::signal::ctrl_c());

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::Behaviour(event) => {
                            println!("Behaviour event: {:?}", event);
                            self.handle_behaviour_event(event).await;
                        },
                        SwarmEvent::NewListenAddr { address, .. } => {
                            println!("New listen address: {:?}", address);
                        },
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            println!("Connection established with: {:?}", peer_id);
                        },
                        SwarmEvent::ConnectionClosed { peer_id, .. } => {
                            println!("Connection closed with: {:?}", peer_id);
                        },
                        _ => {
                            println!("Other event: {:?}", event);
                        }
                    }
                }
                _ = &mut ctrl_c => {
                    println!("Ctrl+C received");
                    break;
                }
            }
        }
        Ok(())
    }

    async fn handle_behaviour_event(&mut self, event: P2PBehaviourEvent) {
        match event {
            P2PBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            }) => {
                println!("Gossipsub message: {:?}", message);
            }
            P2PBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic }) => {
                println!("Gossipsub subscribed to topic: {:?}", topic);
            }
            P2PBehaviourEvent::Gossipsub(gossipsub::Event::Unsubscribed { peer_id, topic }) => {
                println!("Gossipsub unsubscribed from topic: {:?}", topic);
            }
            P2PBehaviourEvent::Gossipsub(gossipsub::Event::GossipsubNotSupported { .. }) => {
                println!("Gossipsub not supported");
            }
            P2PBehaviourEvent::Mdns(event) => {
                println!("Mdns event: {:?}", event);
            }
        }
    }
}
