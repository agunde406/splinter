// Copyright 2019 Cargill Incorporated
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

mod error;
mod heartbeat_monitor;
mod messages;

use std;
use std::cmp::min;
use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::Instant;

pub use error::ConnectionManagerError;
use heartbeat_monitor::{HbShutdownHandle, HeartbeatMonitor};
pub use messages::{CmMessage, CmNotification, CmPayload, CmRequest, CmResponse, CmResponseStatus};
use protobuf::Message;
use uuid::Uuid;

use crate::matrix::{MatrixLifeCycle, MatrixSender};
use crate::protos::network::{NetworkHeartbeat, NetworkMessage, NetworkMessageType};
use crate::transport::Transport;

const DEFAULT_HEARTBEAT_INTERVAL: u64 = 10;
const INITIAL_RETRY_FREQUENCY: u64 = 10;
const MAXIMUM_RETRY_FREQUENCY: u64 = 300;
const MAXIMUM_RETRY_ATTEMPTS: u64 = 10;

// TODO add plenty of logging for reconnection
pub struct ConnectionManager<T: 'static, U: 'static>
where
    T: MatrixLifeCycle,
    U: MatrixSender,
{
    hb_monitor: HeartbeatMonitor,
    connection_state: ConnectionState<T, U>,
    join_handle: Option<thread::JoinHandle<()>>,
    sender: Option<Sender<CmMessage>>,
    shutdown_handle: Option<ShutdownHandle>,
}

impl<T, U> ConnectionManager<T, U>
where
    T: MatrixLifeCycle,
    U: MatrixSender,
{
    pub fn new(
        life_cycle: T,
        matrix_sender: U,
        transport: Box<dyn Transport + Send>,
        heartbeat_interval: Option<u64>,
    ) -> Self {
        let heartbeat = heartbeat_interval.unwrap_or(DEFAULT_HEARTBEAT_INTERVAL);
        let connection_state = ConnectionState::new(life_cycle, matrix_sender, transport);
        let hb_monitor = HeartbeatMonitor::new(heartbeat);

        Self {
            hb_monitor,
            connection_state,
            join_handle: None,
            sender: None,
            shutdown_handle: None,
        }
    }

    pub fn start(&mut self) -> Result<Connector, ConnectionManagerError> {
        let (sender, recv) = channel();
        let mut state = self.connection_state.clone();

        let join_handle = thread::Builder::new()
            .name("Connection Manager".into())
            .spawn(move || {
                let mut subscribers = HashMap::new();
                loop {
                    match recv.recv() {
                        Ok(CmMessage::Shutdown) => break,
                        Ok(CmMessage::Subscribe(id, sender)) => {
                            subscribers.insert(id, sender);
                        }
                        Ok(CmMessage::UnSubscribe(ref id)) => {
                            subscribers.remove(id);
                        }
                        Ok(CmMessage::Request(req)) => {
                            handle_request(req, &mut state);
                        }
                        Ok(CmMessage::SendHeartbeats) => {
                            send_heartbeats(&mut state, &mut subscribers)
                        }
                        Err(_) => {
                            warn!("All senders have disconnected");
                            break;
                        }
                    }
                }
            })?;

        self.hb_monitor.start(sender.clone())?;
        self.join_handle = Some(join_handle);
        self.shutdown_handle = Some(ShutdownHandle {
            sender: sender.clone(),
            hb_shutdown_handle: self.hb_monitor.shutdown_handle().unwrap(),
        });
        self.sender = Some(sender.clone());

        Ok(Connector { sender })
    }

    pub fn shutdown_handle(&self) -> Option<ShutdownHandle> {
        self.shutdown_handle.clone()
    }

    pub fn await_shutdown(self) {
        self.hb_monitor.await_shutdown();

        let join_handle = if let Some(jh) = self.join_handle {
            jh
        } else {
            return;
        };

        if let Err(err) = join_handle.join() {
            error!(
                "Connection manager thread did not shutdown correctly: {:?}",
                err
            );
        }
    }

    pub fn shutdown_and_wait(self) {
        if let Some(sh) = self.shutdown_handle.clone() {
            sh.shutdown();
        } else {
            return;
        }

        self.await_shutdown();
    }
}

#[derive(Clone)]
pub struct Connector {
    sender: Sender<CmMessage>,
}

impl Connector {
    pub fn request_connection(&self, endpoint: &str) -> Result<CmResponse, ConnectionManagerError> {
        self.send_payload(CmPayload::AddConnection {
            endpoint: endpoint.to_string(),
        })
    }

    pub fn remove_connection(&self, endpoint: &str) -> Result<CmResponse, ConnectionManagerError> {
        self.send_payload(CmPayload::RemoveConnection {
            endpoint: endpoint.to_string(),
        })
    }

    pub fn subscribe(&self) -> Result<NotificationHandler, ConnectionManagerError> {
        let id = Uuid::new_v4().to_string();
        let (send, recv) = channel();
        match self.sender.send(CmMessage::Subscribe(id.clone(), send)) {
            Ok(()) => Ok(NotificationHandler {
                id,
                recv,
                sender: self.sender.clone(),
            }),
            Err(_) => Err(ConnectionManagerError::SendMessageError(
                "The connection manager is no longer running".into(),
            )),
        }
    }

    fn send_payload(&self, payload: CmPayload) -> Result<CmResponse, ConnectionManagerError> {
        let (sender, recv) = channel();

        let message = CmMessage::Request(CmRequest { sender, payload });

        match self.sender.send(message) {
            Ok(()) => (),
            Err(_) => {
                return Err(ConnectionManagerError::SendMessageError(
                    "The connection manager is no longer running".into(),
                ))
            }
        };

        recv.recv()
            .map_err(|err| ConnectionManagerError::SendMessageError(format!("{:?}", err)))
    }
}

#[derive(Clone)]
pub struct ShutdownHandle {
    sender: Sender<CmMessage>,
    hb_shutdown_handle: HbShutdownHandle,
}

impl ShutdownHandle {
    pub fn shutdown(&self) {
        self.hb_shutdown_handle.shutdown();

        if self.sender.send(CmMessage::Shutdown).is_err() {
            warn!("Connection manager is no longer running");
        }
    }
}

pub struct NotificationHandler {
    id: String,
    sender: Sender<CmMessage>,
    recv: Receiver<CmNotification>,
}

impl NotificationHandler {
    pub fn listen(&self) -> Result<CmNotification, ConnectionManagerError> {
        match self.recv.recv() {
            Ok(notifications) => Ok(notifications),
            Err(_) => Err(ConnectionManagerError::SendMessageError(
                "The connection manager is no longer running".into(),
            )),
        }
    }

    pub fn unsubscribe(&self) -> Result<(), ConnectionManagerError> {
        let message = CmMessage::UnSubscribe(self.id.clone());
        match self.sender.send(message) {
            Ok(()) => Ok(()),
            Err(_) => Err(ConnectionManagerError::SendMessageError(
                "Unsubscribe request timed out".into(),
            )),
        }
    }
}

#[derive(Clone, Debug)]
struct ConnectionMetadata {
    id: usize,
    endpoint: String,
    ref_count: u64,
    reconnecting: bool,
    retry_attempts: u64,
    retry_frequency: u64,
    last_connection_attempt: Instant,
}

#[derive(Clone)]
struct ConnectionState<T, U>
where
    T: MatrixLifeCycle,
    U: MatrixSender,
{
    connections: HashMap<String, ConnectionMetadata>,
    life_cycle: T,
    matrix_sender: U,
    transport: Box<dyn Transport>,
}

impl<T, U> ConnectionState<T, U>
where
    T: MatrixLifeCycle,
    U: MatrixSender,
{
    fn new(life_cycle: T, matrix_sender: U, transport: Box<dyn Transport + Send>) -> Self {
        Self {
            life_cycle,
            matrix_sender,
            transport,
            connections: HashMap::new(),
        }
    }

    fn add_connection(&mut self, endpoint: &str) -> Result<(), ConnectionManagerError> {
        if let Some(meta) = self.connections.get_mut(endpoint) {
            meta.ref_count += 1;
        } else {
            let connection = self.transport.connect(endpoint).map_err(|err| {
                ConnectionManagerError::ConnectionCreationError(format!("{:?}", err))
            })?;

            let id = self.life_cycle.add(connection).map_err(|err| {
                ConnectionManagerError::ConnectionCreationError(format!("{:?}", err))
            })?;

            self.connections.insert(
                endpoint.to_string(),
                ConnectionMetadata {
                    id,
                    endpoint: endpoint.to_string(),
                    ref_count: 1,
                    reconnecting: false,
                    retry_attempts: 0,
                    retry_frequency: INITIAL_RETRY_FREQUENCY,
                    last_connection_attempt: Instant::now(),
                },
            );
        };

        Ok(())
    }

    fn remove_connection(
        &mut self,
        endpoint: &str,
    ) -> Result<Option<ConnectionMetadata>, ConnectionManagerError> {
        let meta = if let Some(meta) = self.connections.get_mut(endpoint) {
            meta.ref_count -= 1;
            meta.clone()
        } else {
            return Ok(None);
        };

        if meta.ref_count < 1 {
            self.connections.remove(endpoint);
            self.life_cycle.remove(meta.id).map_err(|err| {
                ConnectionManagerError::ConnectionRemovalError(format!("{:?}", err))
            })?;
        }

        Ok(Some(meta))
    }

    fn reconnect(
        &mut self,
        endpoint: &str,
        subscribers: &mut HashMap<String, Sender<CmNotification>>,
    ) -> Result<(), ConnectionManagerError> {
        let mut meta = if let Some(meta) = self.connections.get_mut(endpoint) {
            meta.clone()
        } else {
            return Err(ConnectionManagerError::ConnectionRemovalError(
                "Cannot reconnect to endpoint without metadata".into(),
            ));
        };

        if let Ok(connection) = self.transport.connect(endpoint) {
            // remove old mesh id
            if self.life_cycle.remove(meta.id).is_err() {
                trace!(
                    "Connection was already removed from life_cycle: {}",
                    endpoint
                );
            }

            // add new connection to mesh
            let id = self.life_cycle.add(connection).map_err(|err| {
                ConnectionManagerError::ConnectionReconnectError(format!("{:?}", err))
            })?;

            // replace mesh id and reset reconnecting fields
            meta.id = id;
            meta.reconnecting = false;
            meta.retry_attempts = 0;
            meta.retry_frequency = INITIAL_RETRY_FREQUENCY;
            meta.last_connection_attempt = Instant::now();
            self.connections.insert(endpoint.to_string(), meta);

            // Notify subscribers of success
            notify_subscribers(
                subscribers,
                CmNotification::ReconnectAttemptSuccess {
                    endpoint: endpoint.to_string(),
                },
            );
        } else {
            // If connection has reached the maximum number of reconnection attempts, remove
            // connection
            if meta.retry_attempts + 1 > MAXIMUM_RETRY_ATTEMPTS {
                // remove regardless of reference counts
                self.connections.remove(endpoint);
                self.life_cycle.remove(meta.id).map_err(|err| {
                    ConnectionManagerError::ConnectionReconnectError(format!("{:?}", err))
                })?;

                warn!("Unable to reconnnect to {}", endpoint);
                notify_subscribers(
                    subscribers,
                    CmNotification::ReconnectAttemptFailed {
                        endpoint: endpoint.to_string(),
                        message: format!(
                            "Unable to reconnect to {} after {} attempts",
                            endpoint, MAXIMUM_RETRY_ATTEMPTS
                        ),
                    },
                );
                return Ok(());
            }

            // update connections metadata if it still has reconnection attempts left
            meta.retry_attempts += 1;
            meta.reconnecting = true;
            meta.retry_frequency = min(meta.retry_frequency * 2, MAXIMUM_RETRY_FREQUENCY);
            meta.last_connection_attempt = Instant::now();
            println!("{:?}", meta);
            self.connections.insert(endpoint.to_string(), meta);
        }
        Ok(())
    }

    fn connection_metadata(&self) -> HashMap<String, ConnectionMetadata> {
        self.connections.clone()
    }

    fn matrix_sender(&self) -> U {
        self.matrix_sender.clone()
    }
}

fn handle_request<T: MatrixLifeCycle, U: MatrixSender>(
    req: CmRequest,
    state: &mut ConnectionState<T, U>,
) {
    let response = match req.payload {
        CmPayload::AddConnection { ref endpoint } => {
            if let Err(err) = state.add_connection(endpoint) {
                CmResponse::AddConnection {
                    status: CmResponseStatus::Error,
                    error_message: Some(format!("{:?}", err)),
                }
            } else {
                CmResponse::AddConnection {
                    status: CmResponseStatus::OK,
                    error_message: None,
                }
            }
        }
        CmPayload::RemoveConnection { ref endpoint } => match state.remove_connection(endpoint) {
            Ok(Some(_)) => CmResponse::RemoveConnection {
                status: CmResponseStatus::OK,
                error_message: None,
            },
            Ok(None) => CmResponse::RemoveConnection {
                status: CmResponseStatus::ConnectionNotFound,
                error_message: None,
            },
            Err(err) => CmResponse::RemoveConnection {
                status: CmResponseStatus::Error,
                error_message: Some(format!("{:?}", err)),
            },
        },
    };

    if req.sender.send(response).is_err() {
        error!("Requester has dropped its connection to connection manager");
    }
}

fn notify_subscribers(
    subscribers: &mut HashMap<String, Sender<CmNotification>>,
    notification: CmNotification,
) {
    for (id, sender) in subscribers.clone() {
        if sender.send(notification.clone()).is_err() {
            warn!("subscriber has dropped its connection to connection manager");
            subscribers.remove(&id);
        }
    }
}

fn send_heartbeats<T: MatrixLifeCycle, U: MatrixSender>(
    state: &mut ConnectionState<T, U>,
    subscribers: &mut HashMap<String, Sender<CmNotification>>,
) {
    let heartbeat_message = match create_heartbeat() {
        Ok(h) => h,
        Err(err) => {
            error!("Failed to create heartbeat message: {:?}", err);
            return;
        }
    };

    for (endpoint, metadata) in state.connection_metadata() {
        // if connection is already attempting reconnection, call reconnect
        if metadata.reconnecting {
            if metadata.last_connection_attempt.elapsed().as_secs() > metadata.retry_frequency {
                if let Err(err) = state.reconnect(&endpoint, subscribers) {
                    notify_subscribers(
                        subscribers,
                        CmNotification::ReconnectAttemptFailed {
                            endpoint: endpoint.clone(),
                            message: format!("{:?}", err),
                        },
                    );
                }
            }
        } else {
            info!("Sending heartbeat to {}", endpoint);
            if let Err(err) = state
                .matrix_sender()
                .send(metadata.id, heartbeat_message.clone())
            {
                error!(
                    "failed to send heartbeat: {:?} attempting reconnection",
                    err
                );

                notify_subscribers(
                    subscribers,
                    CmNotification::AttemptingReconnect {
                        endpoint: endpoint.clone(),
                    },
                );

                if let Err(err) = state.reconnect(&endpoint, subscribers) {
                    error!("Connection reattempt failed: {:?}", err);
                    notify_subscribers(
                        subscribers,
                        CmNotification::ReconnectAttemptFailed {
                            endpoint: endpoint.clone(),
                            message: format!("{:?}", err),
                        },
                    );
                }
            }
        }
    }
}

fn create_heartbeat() -> Result<Vec<u8>, ConnectionManagerError> {
    let heartbeat = NetworkHeartbeat::new().write_to_bytes().map_err(|_| {
        ConnectionManagerError::HeartbeatError("cannot create NetworkHeartbeat message".to_string())
    })?;
    let mut heartbeat_message = NetworkMessage::new();
    heartbeat_message.set_message_type(NetworkMessageType::NETWORK_HEARTBEAT);
    heartbeat_message.set_payload(heartbeat);
    let heartbeat_bytes = heartbeat_message.write_to_bytes().map_err(|_| {
        ConnectionManagerError::HeartbeatError("cannot create NetworkMessage".to_string())
    })?;
    Ok(heartbeat_bytes)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::mesh::Mesh;
    use crate::transport::inproc::InprocTransport;
    use crate::transport::raw::RawTransport;

    #[test]
    fn test_connection_manager_startup_and_shutdown() {
        let mut transport = Box::new(InprocTransport::default());
        transport.listen("inproc://test").unwrap();
        let mesh = Mesh::new(512, 128);

        let mut cm =
            ConnectionManager::new(mesh.get_life_cycle(), mesh.get_sender(), transport, None);

        cm.start().unwrap();
        cm.shutdown_and_wait();
    }

    #[test]
    fn test_notification_handler_subscribe_unsubscribe() {
        let mut transport = Box::new(InprocTransport::default());
        transport.listen("inproc://test").unwrap();
        let mesh = Mesh::new(512, 128);

        let mut cm =
            ConnectionManager::new(mesh.get_life_cycle(), mesh.get_sender(), transport, None);

        let connector = cm.start().unwrap();

        let subscriber = connector.subscribe().unwrap();
        subscriber.unsubscribe().unwrap();

        cm.shutdown_and_wait();
    }

    #[test]
    fn test_add_connection_request() {
        let mut transport = Box::new(InprocTransport::default());
        let mut listener = transport.listen("inproc://test").unwrap();

        thread::spawn(move || {
            listener.accept().unwrap();
        });

        let mesh = Mesh::new(512, 128);
        let mut cm =
            ConnectionManager::new(mesh.get_life_cycle(), mesh.get_sender(), transport, None);
        let connector = cm.start().unwrap();

        let response = connector.request_connection("inproc://test").unwrap();

        assert_eq!(
            response,
            CmResponse::AddConnection {
                status: CmResponseStatus::OK,
                error_message: None
            }
        );

        cm.shutdown_and_wait();
    }

    /// Test that adding the same connection twice is an idempotent operation
    #[test]
    fn test_mutiple_add_connection_requests() {
        let mut transport = Box::new(InprocTransport::default());
        let mut listener = transport.listen("inproc://test").unwrap();

        thread::spawn(move || {
            listener.accept().unwrap();
        });

        let mesh = Mesh::new(512, 128);
        let mut cm =
            ConnectionManager::new(mesh.get_life_cycle(), mesh.get_sender(), transport, None);
        let connector = cm.start().unwrap();

        let response = connector.request_connection("inproc://test").unwrap();

        assert_eq!(
            response,
            CmResponse::AddConnection {
                status: CmResponseStatus::OK,
                error_message: None
            }
        );

        let response = connector.request_connection("inproc://test").unwrap();
        assert_eq!(
            response,
            CmResponse::AddConnection {
                status: CmResponseStatus::OK,
                error_message: None
            }
        );

        cm.shutdown_and_wait();
    }

    /// test_heartbeat_inproc
    ///
    /// Test that heartbeats are correctly sent to connections
    #[test]
    fn test_heartbeat_inproc() {
        let mut transport = Box::new(InprocTransport::default());
        let mut listener = transport.listen("inproc://test").unwrap();
        let mesh = Mesh::new(512, 128);
        let mesh_clone = mesh.clone();

        thread::spawn(move || {
            let conn = listener.accept().unwrap();
            mesh_clone.add(conn).unwrap();
        });

        let mut cm =
            ConnectionManager::new(mesh.get_life_cycle(), mesh.get_sender(), transport, Some(1));
        let connector = cm.start().unwrap();

        let response = connector.request_connection("inproc://test").unwrap();

        assert_eq!(
            response,
            CmResponse::AddConnection {
                status: CmResponseStatus::OK,
                error_message: None
            }
        );

        // Verify mesh received heartbeat

        let envelope = mesh.recv().unwrap();
        let heartbeat: NetworkMessage = protobuf::parse_from_bytes(&envelope.payload()).unwrap();
        assert_eq!(
            heartbeat.get_message_type(),
            NetworkMessageType::NETWORK_HEARTBEAT
        );
    }

    /// test_heartbeat_raw_tcp
    ///
    /// Test that heartbeats are correctly sent to connections
    #[test]
    fn test_heartbeat_raw_tcp() {
        let mut transport = Box::new(RawTransport::default());
        let mut listener = transport.listen("tcp://localhost:8080").unwrap();
        let mesh = Mesh::new(512, 128);
        let mesh_clone = mesh.clone();

        thread::spawn(move || {
            let conn = listener.accept().unwrap();
            mesh_clone.add(conn).unwrap();
        });

        let mut cm =
            ConnectionManager::new(mesh.get_life_cycle(), mesh.get_sender(), transport, Some(1));
        let connector = cm.start().unwrap();

        let response = connector
            .request_connection("tcp://localhost:8080")
            .unwrap();

        assert_eq!(
            response,
            CmResponse::AddConnection {
                status: CmResponseStatus::OK,
                error_message: None
            }
        );

        let envelope = mesh.recv().unwrap();
        let heartbeat: NetworkMessage = protobuf::parse_from_bytes(&envelope.payload()).unwrap();
        assert_eq!(
            heartbeat.get_message_type(),
            NetworkMessageType::NETWORK_HEARTBEAT
        );
    }

    #[test]
    fn test_remove_connection() {
        let mut transport = Box::new(RawTransport::default());
        let mut listener = transport.listen("tcp://localhost:8080").unwrap();
        let mesh = Mesh::new(512, 128);
        let mesh_clone = mesh.clone();

        thread::spawn(move || {
            let conn = listener.accept().unwrap();
            mesh_clone.add(conn).unwrap();
        });

        let mut cm =
            ConnectionManager::new(mesh.get_life_cycle(), mesh.get_sender(), transport, None);
        let connector = cm.start().unwrap();

        let add_response = connector
            .request_connection("tcp://localhost:8080")
            .unwrap();

        assert_eq!(
            add_response,
            CmResponse::AddConnection {
                status: CmResponseStatus::OK,
                error_message: None
            }
        );

        let remove_response = connector.remove_connection("tcp://localhost:8080").unwrap();

        assert_eq!(
            remove_response,
            CmResponse::RemoveConnection {
                status: CmResponseStatus::OK,
                error_message: None
            }
        );
    }

    #[test]
    fn test_remove_nonexistent_connection() {
        let mut transport = Box::new(RawTransport::default());
        let mut listener = transport.listen("tcp://localhost:8080").unwrap();
        let mesh = Mesh::new(512, 128);
        let mesh_clone = mesh.clone();

        thread::spawn(move || {
            let conn = listener.accept().unwrap();
            mesh_clone.add(conn).unwrap();
        });

        let mut cm =
            ConnectionManager::new(mesh.get_life_cycle(), mesh.get_sender(), transport, None);
        let connector = cm.start().unwrap();

        let remove_response = connector.remove_connection("tcp://localhost:8080").unwrap();

        assert_eq!(
            remove_response,
            CmResponse::RemoveConnection {
                status: CmResponseStatus::ConnectionNotFound,
                error_message: None,
            }
        );
    }

    /// test_reconnect_raw_tcp
    ///
    /// Test that if a connection disconnect, the connection manager will detect the connection
    /// has disconnect by trying to send a heartbeat. The connection manger will try to
    /// reconnect to the endpoint
    #[test]
    fn test_reconnect_raw_tcp() {
        let mut transport = Box::new(RawTransport::default());
        let mut listener = transport.listen("tcp://localhost:8080").unwrap();
        let mesh1 = Mesh::new(512, 128);
        let mesh2 = Mesh::new(512, 128);

        thread::spawn(move || {
            let conn = listener.accept().unwrap();
            println!("received connection");
            let id = mesh2.add(conn).unwrap();
            println!("added connection to mesh");
            // Verify mesh received heartbeat
            let envelope = mesh2.recv().unwrap();
            let heartbeat: NetworkMessage =
                protobuf::parse_from_bytes(&envelope.payload()).unwrap();
            assert_eq!(
                heartbeat.get_message_type(),
                NetworkMessageType::NETWORK_HEARTBEAT
            );
            println!("received heartbeat");

            // remove connection
            let mut connection = mesh2.remove(id).unwrap();
            connection.disconnect().unwrap();
            println!("disconnected connection");
            listener.accept().unwrap();
        });

        let mut cm = ConnectionManager::new(
            mesh1.get_life_cycle(),
            mesh1.get_sender(),
            transport,
            Some(1),
        );
        let connector = cm.start().unwrap();

        let response = connector
            .request_connection("tcp://localhost:8080")
            .unwrap();

        assert_eq!(
            response,
            CmResponse::AddConnection {
                status: CmResponseStatus::OK,
                error_message: None
            }
        );

        let subscriber = connector.subscribe().unwrap();

        // receive reconnecting attempt
        let reconnecting_notification = subscriber.listen().unwrap();
        println!("notification {:?}", reconnecting_notification);
        assert!(
            reconnecting_notification
                == CmNotification::AttemptingReconnect {
                    endpoint: "tcp://localhost:8080".to_string(),
                }
        );

        // receive reconnecting attempt
        let reconnection_notification = subscriber.listen().unwrap();
        println!("notification {:?}", reconnection_notification);
        assert!(
            reconnection_notification
                == CmNotification::ReconnectAttemptSuccess {
                    endpoint: "tcp://localhost:8080".to_string(),
                }
        );
    }
}
