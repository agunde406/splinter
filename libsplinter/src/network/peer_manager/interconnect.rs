// Copyright 2018-2020 Cargill Incorporated
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::sync::mpsc::{channel, Receiver};
use std::sync::{atomic::AtomicBool, Arc, Mutex};
use std::thread;

use crate::collections::BiHashMap;
use crate::matrix::{MatrixReceiver, MatrixSender};
use crate::network::dispatch::{DispatchLoop, DispatchMessage, Dispatcher};
use crate::network::sender::SendRequest;
use crate::protos::network::{NetworkMessage, NetworkMessageType};

use super::connector::PeerManagerConnector;
use super::error::PeerInterconnectError;

// TODO figure out shutdown, probably need to wrap SendRequest
// TODO Remove unwraps/expects
// TODO Add errors
// TODO update peer manager to return peer id to unique id map
pub struct PeerInterconnect<T: 'static, U: 'static>
where
    T: MatrixReceiver,
    U: MatrixSender,
{
    peer_connector: PeerManagerConnector,
    // peer id to unique id
    // TODO can this be done without a lock, two threads will need the peer map so probably not
    peers: Arc<Mutex<BiHashMap<String, String>>>,
    message_receiver: Option<T>,
    message_sender: Option<U>,
    // TODO Should the PeerInterconnect run all dispatch loops, or just NetworkMessage dispatchers?
    network_dispatcher: Option<Dispatcher<NetworkMessageType>>,
    // the receiver for messages from handlers that need to be sent over the network
    // the senders have been added to the handlers that will send messages
    dispatched_receiver: Option<Receiver<SendRequest>>,
    // TODO remove dispatch loops requirment for running
    running: Arc<AtomicBool>,
}

impl<T, U> PeerInterconnect<T, U>
where
    T: MatrixReceiver,
    U: MatrixSender,
{
    pub fn new(
        peer_connector: PeerManagerConnector,
        message_receiver: T,
        message_sender: U,
        network_dispatcher: Dispatcher<NetworkMessageType>,
        dispatched_receiver: Receiver<SendRequest>,
        running: Arc<AtomicBool>,
    ) -> Self {
        PeerInterconnect {
            peer_connector,
            peers: Arc::new(Mutex::new(BiHashMap::new())),
            message_receiver: Some(message_receiver),
            message_sender: Some(message_sender),
            network_dispatcher: Some(network_dispatcher),
            dispatched_receiver: Some(dispatched_receiver),
            running,
        }
    }

    // TODO add shutdown handle
    pub fn start(&mut self) -> Result<(), PeerInterconnectError> {
        // start dispatcher loop for network message
        let (network_dispatch_send, network_dispatch_recv) = channel();
        let network_dispatcher = self
            .network_dispatcher
            .take()
            .ok_or_else(|| PeerInterconnectError::StartUpError("Already started".to_string()))?;
        let network_dispatch_loop = DispatchLoop::new(
            Box::new(network_dispatch_recv),
            network_dispatcher,
            self.running.clone(),
        );
        let network_dispatcher_thread = thread::spawn(move || network_dispatch_loop.run());

        // start receiver loop
        let message_receiver = self
            .message_receiver
            .take()
            .ok_or_else(|| PeerInterconnectError::StartUpError("Already started".to_string()))?;
        let recv_peers = self.peers.clone();
        let recv_peer_connector = self.peer_connector.clone();
        let recv_join_handle = thread::Builder::new()
            .name("Peer Interconnect Receiver".into())
            .spawn(move || {
                loop {
                    // receive messages from peers
                    let envelope = match message_receiver.recv() {
                        Ok(envelope) => envelope,
                        Err(err) => {
                            error!("Unable to receive message: {}", err);
                            break;
                        }
                    };

                    let connection_id = envelope.id();
                    let peer_id = {
                        let mut peers = match recv_peers.lock() {
                            Ok(recv_peers) => recv_peers,
                            Err(_) => {
                                error!("PeerInterconnect state has been poisoned");
                                break;
                            }
                        };

                        let mut peer_id = peers
                            .get_by_value(connection_id)
                            .unwrap_or(&"".to_string())
                            .to_string();

                        // convert connection id to peer id
                        // if peer id is None, fetch peers to see if they have changed
                        // TODO should this happen everytime peer_id is none, possibly attack
                        if peer_id.is_empty() {
                            *peers = match recv_peer_connector.connection_ids() {
                                Ok(peers) => peers,
                                Err(err) => {
                                    error!("Unable to get peer map: {}", err);
                                    break;
                                }
                            };
                            peer_id = peers
                                .get_by_value(connection_id)
                                .to_owned()
                                .unwrap_or(&"".to_string())
                                .to_string();
                        }
                        peer_id
                    };

                    // If we have the peer, pass message to dispatcher, else print error
                    if !peer_id.is_empty() {
                        let mut msg: NetworkMessage =
                            match protobuf::parse_from_bytes(envelope.payload()) {
                                Ok(msg) => msg,
                                Err(err) => {
                                    warn!("Received invalid network message: {}", err);
                                    continue;
                                }
                            };

                        let dispatch_msg = DispatchMessage::new(
                            msg.get_message_type(),
                            msg.take_payload(),
                            peer_id.to_string(),
                        );
                        trace!(
                            "Received Message from {}: {:?}",
                            peer_id,
                            msg.get_message_type()
                        );
                        match network_dispatch_send.send(dispatch_msg) {
                            Ok(()) => (),
                            Err(err) => error!("Dispatch Error {}", err.to_string()),
                        }
                    } else {
                        error!("Received message from unknown peer");
                    }
                }
            });

        // start thread for sending message
        let dispatched_receiver = self
            .dispatched_receiver
            .take()
            .ok_or_else(|| PeerInterconnectError::StartUpError("Already started".to_string()))?;
        let send_peers = self.peers.clone();
        let message_sender = self
            .message_sender
            .take()
            .ok_or_else(|| PeerInterconnectError::StartUpError("Already started".to_string()))?;
        let send_peer_connector = self.peer_connector.clone();
        let send_join_handle = thread::Builder::new()
            .name("Peer Interconnect Sender".into())
            .spawn(move || {
                loop {
                    // receive message from internal handlers to send over the network
                    let request = match dispatched_receiver.recv() {
                        Ok(SendRequest::Request(request)) => request,
                        Ok(SendRequest::Shutdown) => {
                            info!("Received Shutdown");
                            break;
                        }
                        Err(err) => {
                            error!("Unable to receive message form handlers: {}", err);
                            break;
                        }
                    };
                    let recipient = request.recipient();
                    // convert recipient (peer_id) to connection_id
                    let connection_id = {
                        let mut peers = match send_peers.lock() {
                            Ok(recv_peers) => recv_peers,
                            Err(_) => {
                                error!("PeerInterconnect state has been poisoned");
                                break;
                            }
                        };

                        let mut connection_id = peers
                            .get_by_key(recipient)
                            .to_owned()
                            .unwrap_or(&"".to_string())
                            .to_string();

                        if connection_id.is_empty() {
                            *peers = match send_peer_connector.connection_ids() {
                                Ok(peers) => peers,
                                Err(err) => {
                                    error!("Unable to get peer map: {}", err);
                                    break;
                                }
                            };

                            connection_id = peers
                                .get_by_key(recipient)
                                .to_owned()
                                .unwrap_or(&"".to_string())
                                .to_string();
                        }
                        connection_id
                    };

                    // if peer exists, send message over the network
                    if !connection_id.is_empty() {
                        // TODO change SendRequest so we don't need to copy (to_vec) here
                        match message_sender
                            .send(connection_id.to_string(), request.payload().to_vec())
                        {
                            Ok(_) => (),
                            Err(err) => {
                                error!("Unable to send message to {}", err);
                            }
                        }
                    } else {
                        error!("Cannot send message, unknown peer: {}", recipient);
                    }
                }
            });
        Ok(())
    }

    // TODO shutdown, this will require wrapping SendRequest in enum with Request and Shutdown
    // This will be a breaking change so should go into the long lived branch
    pub fn shutdown() {
        unimplemented!()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use protobuf::Message;

    use std::sync::mpsc::Sender;

    use crate::channel::Sender as SenderTrait;
    use crate::mesh::{Envelope, Mesh};
    use crate::network::connection_manager::ConnectionManager;
    use crate::network::dispatch::{DispatchError, Handler, MessageContext};
    use crate::network::peer_manager::PeerManager;
    use crate::network::sender::HandlerRequest;
    use crate::protos::network::NetworkEcho;
    use crate::transport::{inproc::InprocTransport, Transport};

    // Verify that the PeerInterconnect properly receive messages from peers, passes them to
    // the dispatcher, and sends messages from the handlers to other peers.
    //
    // PeerInterconnect will receive a message from peer test_peer and pass it to
    // NetworkTestHandler. This handler will validate it came from test_peer. The handler will
    // then send a message to the PeerInterconnect to send the message back to test_peer.
    // This valdiates that messages can be sent and recieved over the PeerInterconnect.
    //
    // This tests also validates that PeerInterconnect can retrieve the list of peers from the
    // PeerManager using the PeerManagerConnector.
    #[test]
    fn test_peer_interconnect() {
        let mut transport = Box::new(InprocTransport::default());
        let mut listener = transport
            .listen("inproc://test")
            .expect("Cannot listen for connections");
        let mesh1 = Mesh::new(512, 128);
        let mesh2 = Mesh::new(512, 128);

        // set up thread for the peer
        thread::spawn(move || {
            // accept incoming connection and add it to mesh2
            let conn = listener.accept().expect("Cannot accept connection");
            mesh2
                .add(conn, "test_id".to_string())
                .expect("Cannot add connection to mesh");

            // send a NetworkEchoMessage
            let message_bytes = echo_to_network_message_bytes(b"test_retrieve".to_vec());
            let envelope = Envelope::new("test_id".to_string(), message_bytes);
            mesh2.send(envelope).expect("Unable to send message");

            // Verify mesh received the same network echo back
            let envelope = mesh2.recv().expect("Cannot receive message");
            let network_msg: NetworkMessage = protobuf::parse_from_bytes(&envelope.payload())
                .expect("Cannot parse NetworkMessage");

            let echo: NetworkEcho = protobuf::parse_from_bytes(network_msg.get_payload()).unwrap();
            assert_eq!(
                network_msg.get_message_type(),
                NetworkMessageType::NETWORK_ECHO
            );

            assert_eq!(echo.get_payload().to_vec(), b"test_retrieve".to_vec());

            // Send a message back to PeerInterconnect that will shutdown the test
            let message_bytes =
                echo_to_network_message_bytes("shutdown_string".as_bytes().to_vec());
            let envelope = Envelope::new("test_id".to_string(), message_bytes);
            mesh2.send(envelope).expect("Cannot send message");
        });

        let mut cm = ConnectionManager::new(
            mesh1.get_life_cycle(),
            mesh1.get_sender(),
            transport,
            Some(1),
            None,
        );
        let connector = cm.start().unwrap();
        let mut peer_manager = PeerManager::new(connector, None);
        let peer_connector = peer_manager.start().expect("Cannot start peer_manager");
        let peer_ref = peer_connector
            .add_peer_ref("test_peer".to_string(), vec!["test".to_string()])
            .expect("Unable to add peer");

        assert_eq!(peer_ref.peer_id, "test_peer");
        let (send, recv) = channel();

        // Set up thread for PeerInterconnect
        // TODO this thread should be able to be removed once shutdown is finished
        thread::spawn(move || {
            let (disp_send, disp_recv) = channel();
            let mut dispatcher = Dispatcher::new(Box::new(disp_send));
            let running = Arc::new(AtomicBool::new(true));
            let handler = NetworkTestHandler::new(send);
            dispatcher.set_handler(NetworkMessageType::NETWORK_ECHO, Box::new(handler));
            let mut interconnect = PeerInterconnect::new(
                peer_connector,
                mesh1.get_receiver(),
                mesh1.get_sender(),
                dispatcher,
                disp_recv,
                running,
            );

            interconnect.start();
        });

        // wait to be told to shutdown
        recv.recv().expect("Failed to receive message");
        peer_manager.shutdown_and_wait();
        cm.shutdown_and_wait();
    }

    struct Shutdown {}

    struct NetworkTestHandler {
        shutdown_sender: Sender<Shutdown>,
    }

    impl NetworkTestHandler {
        fn new(shutdown_sender: Sender<Shutdown>) -> Self {
            NetworkTestHandler { shutdown_sender }
        }
    }

    impl Handler<NetworkMessageType, NetworkEcho> for NetworkTestHandler {
        fn handle(
            &self,
            message: NetworkEcho,
            message_context: &MessageContext<NetworkMessageType>,
            network_sender: &dyn SenderTrait<SendRequest>,
        ) -> Result<(), DispatchError> {
            let echo_string = String::from_utf8(message.get_payload().to_vec()).unwrap();
            if &echo_string == "shutdown_string" {
                self.shutdown_sender
                    .send(Shutdown {})
                    .expect("Cannot send shutdown");
            } else {
                assert_eq!(message_context.source_peer_id(), "test_peer");
                let echo_bytes = message.write_to_bytes().unwrap();

                let mut network_msg = NetworkMessage::new();
                network_msg.set_message_type(NetworkMessageType::NETWORK_ECHO);
                network_msg.set_payload(echo_bytes);
                let network_msg_bytes = network_msg.write_to_bytes().unwrap();

                let request = SendRequest::Request(HandlerRequest::new(
                    message_context.source_peer_id().to_string(),
                    network_msg_bytes,
                ));

                network_sender.send(request).expect("Cannot send message");
            }

            Ok(())
        }
    }

    fn echo_to_network_message_bytes(echo_bytes: Vec<u8>) -> Vec<u8> {
        let mut echo_message = NetworkEcho::new();
        echo_message.set_payload(echo_bytes);
        let echo_message_bytes = echo_message.write_to_bytes().unwrap();

        let mut network_message = NetworkMessage::new();
        network_message.set_message_type(NetworkMessageType::NETWORK_ECHO);
        network_message.set_payload(echo_message_bytes);
        network_message.write_to_bytes().unwrap()
    }
}
