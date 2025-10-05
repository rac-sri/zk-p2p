use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha256::digest;

use tokio::sync::mpsc;

use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_crypto_primitives::crh::CRHScheme;
use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_groth16::Groth16;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::rand::SeedableRng;

use libp2p::{
    Multiaddr, PeerId, Swarm, Transport,
    futures::StreamExt,
    gossipsub::{self, IdentTopic, MessageAuthenticity, MessageId},
    identify, mdns, noise,
    swarm::{Config, NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};

use crate::zk::{PedersenCircuit, Window};

#[derive(Serialize, Deserialize)]
struct ProofMessage {
    proof: Vec<u8>,
    hash_x: Vec<u8>,
    hash_y: Vec<u8>,
}

pub enum NodeCommand {
    SendMessage(String, String),
    ConnectToPeer(String),
}
#[derive(NetworkBehaviour)]
pub struct P2PBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
    identity: identify::Behaviour,
}

pub struct NetworkNode {
    pub(crate) swarm: Swarm<P2PBehaviour>,
    command_receiver: mpsc::UnboundedReceiver<NodeCommand>,
    command_sender: mpsc::UnboundedSender<NodeCommand>,
    proving_key: ark_groth16::ProvingKey<Bls12_381>,
    verifying_key: ark_groth16::VerifyingKey<Bls12_381>,
    crh_params: ark_crypto_primitives::crh::pedersen::Parameters<JubJub>,
}

impl NetworkNode {
    pub fn new(port: u16) -> Self {
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(keypair.public());

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .validation_mode(gossipsub::ValidationMode::Permissive)
            .build()
            .expect("Valid config");
        let behaviour = P2PBehaviour {
            gossipsub: gossipsub::Behaviour::new(MessageAuthenticity::Anonymous, gossipsub_config)
                .unwrap(),
            mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id).unwrap(),
            identity: identify::Behaviour::new(identify::Config::new(
                "/p2p-zk-blockchain/1.0.0".to_string(),
                keypair.public(),
            )),
        };

        type CRH = ark_crypto_primitives::crh::pedersen::CRH<JubJub, Window>;

        let mut rng = ark_std::rand::rngs::StdRng::from_seed([1; 32]);
        let parameters = CRH::setup(&mut rng).unwrap();

        let dummy_message = vec![Fr::rand(&mut rng); 3];
        let dummy_hash_result = CRH::evaluate(&parameters, "dummy".as_bytes()).unwrap();

        let dummy_circuit = PedersenCircuit::new(dummy_message, &parameters, &dummy_hash_result);

        let (proving_key, verifying_key) =
            Groth16::<Bls12_381>::setup(dummy_circuit, &mut rng).unwrap();

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
        let (command_sender, command_receiver) = mpsc::unbounded_channel();

        let listen_addr = format!("/ip4/0.0.0.0/tcp/{}", port);
        swarm.listen_on(listen_addr.parse().unwrap()).unwrap();
        println!("🎧 Listening on {}", listen_addr);
        println!("✨ Node initialization complete!\n");

        Self {
            swarm,
            command_receiver,
            command_sender,
            proving_key,
            verifying_key,
            crh_params: parameters,
        }
    }

    pub async fn connect_to_peer(&mut self, addr: &str) -> Result<(), String> {
        println!("🔌 Connecting to peer: {}", addr);
        let addr: Multiaddr = addr.parse().unwrap();
        self.swarm.dial(addr).unwrap();
        Ok(())
    }

    pub fn get_command_sender(&self) -> mpsc::UnboundedSender<NodeCommand> {
        self.command_sender.clone()
    }

    pub async fn subscribe_to_topic(&mut self, topic_name: &str) -> Result<(), String> {
        let topic = IdentTopic::new(topic_name);
        self.swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&topic)
            .map_err(|e| format!("Failed to subscribe to topic: {}", e))?;
        println!("📬 Subscribed to topic: '{}'", topic_name);
        Ok(())
    }

    pub fn send_message(&mut self, topic_name: &str, message: &str) -> Result<MessageId, String> {
        println!("\n📤 Preparing to send message: '{}'", message);

        let mut rng = ark_std::test_rng();
        let num_generators = 3;
        let mut generators = Vec::with_capacity(num_generators);
        for _ in 0..num_generators {
            generators.push(G1Affine::rand(&mut rng));
        }

        let message_fr = self.string_to_fr_vec(message, 3);
        println!("  ⚙️  Converted message to field elements");

        // Convert message_fr to bytes (same way as in circuit)
        let input_bytes: Vec<u8> = message_fr
            .iter()
            .flat_map(|x| x.into_bigint().to_bytes_le())
            .collect();

        type CRH = ark_crypto_primitives::crh::pedersen::CRH<JubJub, Window>;
        let hash_result = CRH::evaluate(&self.crh_params, input_bytes.as_slice()).unwrap();
        println!("  🔐 Computed Pedersen hash");

        let circuit = PedersenCircuit::new(message_fr.clone(), &self.crh_params, &hash_result);

        println!("  🧮 Generating ZK proof...");
        let mut rng = ark_std::rand::rngs::StdRng::from_seed([1; 32]);
        let proof = Groth16::<Bls12_381>::prove(&self.proving_key, circuit, &mut rng).unwrap();
        println!("  ✅ ZK proof generated");
        let mut buffer = Vec::new();
        proof.serialize_uncompressed(&mut buffer).unwrap();

        let mut proof_bytes = Vec::new();
        proof.serialize_uncompressed(&mut proof_bytes).unwrap();

        // Serialize hash coordinates
        let mut hash_x = Vec::new();
        let mut hash_y = Vec::new();
        hash_result.x.serialize_uncompressed(&mut hash_x).unwrap();
        hash_result.y.serialize_uncompressed(&mut hash_y).unwrap();

        let message_data = ProofMessage {
            proof: proof_bytes,
            hash_x,
            hash_y,
        };

        let serialized = serde_json::to_vec(&message_data).unwrap();
        println!("  📦 Packaged proof + hash ({} bytes)", serialized.len());

        let topic = IdentTopic::new(topic_name);
        let message_id = self
            .swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic, serialized)
            .map_err(|e| format!("Failed to publish message: {}", e))?;

        println!(
            "  🚀 Published to topic '{}' (MessageId: {})\n",
            topic_name, message_id
        );
        Ok(message_id)
    }

    pub fn verify_message(&self, proof: Vec<u8>) -> Result<bool, String> {
        let data: ProofMessage =
            serde_json::from_slice(&proof).map_err(|e| format!("Failed to deserialize: {}", e))?;

        let proof = ark_groth16::Proof::deserialize_uncompressed(data.proof.as_slice()).unwrap();
        use ark_ed_on_bls12_381::Fq;
        let hash_x = Fq::deserialize_uncompressed(data.hash_x.as_slice()).unwrap();
        let hash_y = Fq::deserialize_uncompressed(data.hash_y.as_slice()).unwrap();

        let mut x_bytes = Vec::new();
        hash_x.serialize_uncompressed(&mut x_bytes).unwrap();
        let mut y_bytes = Vec::new();
        hash_y.serialize_uncompressed(&mut y_bytes).unwrap();

        let public_x = Fr::from_le_bytes_mod_order(&x_bytes);
        let public_y = Fr::from_le_bytes_mod_order(&y_bytes);

        let verifier =
            Groth16::<Bls12_381>::verify(&self.verifying_key, &[public_x, public_y], &proof)
                .unwrap();
        Ok(verifier)
    }

    pub async fn run(&mut self) -> Result<(), String> {
        let mut ctrl_c = Box::pin(tokio::signal::ctrl_c());

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::Behaviour(event) => {
                            self.handle_behaviour_event(event).await;
                        },
                        SwarmEvent::NewListenAddr { address, .. } => {
                            println!("🌐 Listening on: {}", address);
                        },
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                            println!("🤝 Connection established with: {} ({})", peer_id, endpoint.get_remote_address());
                            self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        },
                        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                            println!("👋 Connection closed with: {} ({:?})", peer_id, cause);
                        },
                        _ => {
                            println!("Other event: {:?}", event);
                        }
                    }
                }
                command = self.command_receiver.recv() => {
                    match command {
                        Some(command) => {
                            self.handle_command(command).await;
                        }
                        None => {
                            println!("No command received");
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

    fn string_to_fr_vec(&self, message: &str, length: usize) -> Vec<Fr> {
        let mut result = Vec::with_capacity(length);
        let message_bytes = message.as_bytes();

        for i in 0..length {
            let hash = digest(format!("{}", message_bytes[i]));
            result.push(Fr::from_le_bytes_mod_order(&hash.as_bytes()));
        }

        result
    }

    async fn handle_command(&mut self, command: NodeCommand) {
        match command {
            NodeCommand::SendMessage(topic, message) => {
                self.send_message(&topic, &message).unwrap();
            }
            NodeCommand::ConnectToPeer(addr) => {
                self.connect_to_peer(&addr).await.unwrap();
            }
        }
    }
    async fn handle_behaviour_event(&mut self, event: P2PBehaviourEvent) {
        match event {
            P2PBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            }) => {
                println!("\n📨 Received message from peer: {}", propagation_source);
                println!("  📋 Message ID: {}", message_id);
                println!("  📊 Size: {} bytes", message.data.len());

                // Deserialize and verify the proof
                print!("  🔍 Verifying ZK proof... ");
                match self.verify_message(message.data.clone()) {
                    Ok(true) => {
                        println!("✅ VALID");
                        println!("  🎉 Proof verified successfully!\n");
                        // TODO: sign the message using your public key
                    }
                    Ok(false) => {
                        println!("❌ INVALID");
                        println!("  ⚠️  Proof verification failed!\n");
                    }
                    Err(e) => {
                        println!("💥 ERROR");
                        println!("  ⚠️  Error: {}\n", e);
                    }
                }
            }
            P2PBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id: _, topic }) => {
                println!("📢 Peer subscribed to topic: {}", topic);
            }
            P2PBehaviourEvent::Gossipsub(gossipsub::Event::Unsubscribed { peer_id: _, topic }) => {
                println!("📵 Peer unsubscribed from topic: {}", topic);
            }
            P2PBehaviourEvent::Gossipsub(gossipsub::Event::GossipsubNotSupported { .. }) => {
                println!("⚠️  Gossipsub not supported by peer");
            }
            P2PBehaviourEvent::Mdns(mdns::Event::Discovered(list)) => {
                println!("🔍 mDNS discovered {} peer(s)", list.len());
                for (peer_id, multiaddr) in list {
                    println!("  ➕ Peer: {} at {}", peer_id, multiaddr);
                    self.swarm
                        .behaviour_mut()
                        .gossipsub
                        .add_explicit_peer(&peer_id);
                }
            }
            P2PBehaviourEvent::Mdns(mdns::Event::Expired(list)) => {
                println!("⏰ {} peer(s) expired via mDNS", list.len());
                for (peer_id, multiaddr) in list {
                    println!("  ➖ Peer: {} at {}", peer_id, multiaddr);
                    self.swarm
                        .behaviour_mut()
                        .gossipsub
                        .remove_explicit_peer(&peer_id);
                }
            }
            P2PBehaviourEvent::Identity(identify::Event::Received { peer_id, info }) => {
                println!("🆔 Identified peer: {}", peer_id);
                println!("  📋 Protocol: {}", info.protocol_version);
                println!("  🔑 Public Key: {:?}", info.public_key);
            }
            P2PBehaviourEvent::Identity(identify::Event::Sent { peer_id }) => {
                println!("📤 Sent identity to peer: {}", peer_id);
            }
            P2PBehaviourEvent::Identity(identify::Event::Pushed { peer_id, info: _ }) => {
                println!("🔄 Pushed updated identity to peer: {}", peer_id);
            }
            P2PBehaviourEvent::Identity(identify::Event::Error { peer_id, error }) => {
                println!("❌ Identity error with {}: {:?}", peer_id, error);
            }
        }
    }
}
