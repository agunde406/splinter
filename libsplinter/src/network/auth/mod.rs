// Copyright 2018-2021 Cargill Incorporated
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

mod connection_manager;
mod handlers;
mod pool;

use std::collections::HashMap;
use std::fmt;
use std::sync::{mpsc, Arc, Mutex};

use protobuf::Message;

#[cfg(feature = "trust-authorization")]
use crate::protocol::authorization::AuthProtocolRequest;
use crate::protocol::authorization::AuthorizationMessage;
#[cfg(not(feature = "trust-authorization"))]
use crate::protocol::authorization::ConnectRequest;
#[cfg(feature = "trust-authorization")]
use crate::protocol::{PEER_AUTHORIZATION_PROTOCOL_MIN, PEER_AUTHORIZATION_PROTOCOL_VERSION};
use crate::protos::authorization;
use crate::protos::network::{NetworkMessage, NetworkMessageType};
use crate::protos::prelude::*;
use crate::transport::{Connection, RecvError};

use self::handlers::create_authorization_dispatcher;
use self::pool::{ThreadPool, ThreadPoolBuilder};

const AUTHORIZATION_THREAD_POOL_SIZE: usize = 8;

/// The states of a connection during authorization.
#[derive(PartialEq, Debug, Clone)]
pub(crate) enum AuthorizationState {
    Unknown,

    // v0 authorization states
    Connecting,
    RemoteIdentified(String),
    RemoteAccepted,
    // Set for remote state if useing v0 authorization because the state of both connection is
    // track together
    NotApplicable,

    // v1 authorization states
    #[cfg(feature = "trust-authorization")]
    ProtocolAgreeing,
    #[cfg(feature = "trust-authorization")]
    TrustIdentified(String),
    #[cfg(feature = "trust-authorization")]
    Authorized(String),

    AuthComplete(String),
    Unauthorized,
}

impl fmt::Display for AuthorizationState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            AuthorizationState::Unknown => "Unknown",
            // v0 authorization states
            AuthorizationState::Connecting => "Connecting",
            AuthorizationState::RemoteIdentified(_) => "Remote Identified",
            AuthorizationState::RemoteAccepted => "Remote Accepted",
            AuthorizationState::NotApplicable => "Not Applicable",

            // v1 authorization states
            #[cfg(feature = "trust-authorization")]
            AuthorizationState::ProtocolAgreeing => "Protocol Agreeing",
            #[cfg(feature = "trust-authorization")]
            AuthorizationState::TrustIdentified(_) => "Trust Identified",
            #[cfg(feature = "trust-authorization")]
            AuthorizationState::Authorized(_) => "Authorized",

            AuthorizationState::AuthComplete(_) => "Authorization Complete",
            AuthorizationState::Unauthorized => "Unauthorized",
        })
    }
}

/// Used to track both the local nodes authorization state and the authorization state of the
/// remote node. For v1, authorization is happening in parallel so the states must be tracked
/// separately. For v0, remote_state is set to NotApplicable.
#[derive(Debug, Clone)]
struct ManagedAuthorizationState {
    // Local node state
    state: AuthorizationState,
    // Remove node state
    remote_state: AuthorizationState,
}

type Identity = String;

/// The state transitions that can be applied on a connection during authorization.
#[derive(PartialEq, Debug)]
pub(crate) enum AuthorizationAction {
    // v0 actions
    Connecting,
    TrustIdentifyingV0(Identity),
    Unauthorizing,
    RemoteAuthorizing,

    // v1 actions
    #[cfg(feature = "trust-authorization")]
    ProtocolAgreeing,
    #[cfg(feature = "trust-authorization")]
    TrustIdentifying(Identity),
    #[cfg(feature = "trust-authorization")]
    Authorizing,
}

impl fmt::Display for AuthorizationAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            // v0 actions
            AuthorizationAction::Connecting => f.write_str("Connecting"),
            AuthorizationAction::TrustIdentifyingV0(_) => f.write_str("TrustIdentifyingV0"),
            AuthorizationAction::Unauthorizing => f.write_str("Unauthorizing"),
            AuthorizationAction::RemoteAuthorizing => f.write_str("RemoteAuthorizing"),
            // v1 actions
            #[cfg(feature = "trust-authorization")]
            AuthorizationAction::ProtocolAgreeing => f.write_str("ProtocolAgreeing"),
            #[cfg(feature = "trust-authorization")]
            AuthorizationAction::TrustIdentifying(_) => f.write_str("TrustIdentifying"),
            #[cfg(feature = "trust-authorization")]
            AuthorizationAction::Authorizing => f.write_str("Authorizing"),
        }
    }
}

/// The errors that may occur for a connection during authorization.
#[derive(PartialEq, Debug)]
pub(crate) enum AuthorizationActionError {
    AlreadyConnecting,
    InvalidMessageOrder(AuthorizationState, AuthorizationAction),
    InternalError(String),
}

impl fmt::Display for AuthorizationActionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthorizationActionError::AlreadyConnecting => {
                f.write_str("Already attempting to connect")
            }
            AuthorizationActionError::InvalidMessageOrder(start, action) => {
                write!(f, "Attempting to transition from {} via {}", start, action)
            }
            AuthorizationActionError::InternalError(msg) => f.write_str(&msg),
        }
    }
}

#[derive(Debug)]
pub struct AuthorizationManagerError(pub String);

impl std::error::Error for AuthorizationManagerError {}

impl fmt::Display for AuthorizationManagerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Manages authorization states for connections on a network.
pub struct AuthorizationManager {
    local_identity: String,
    thread_pool: ThreadPool,
    shared: Arc<Mutex<ManagedAuthorizations>>,
}

impl AuthorizationManager {
    /// Constructs an AuthorizationManager
    pub fn new(local_identity: String) -> Result<Self, AuthorizationManagerError> {
        let thread_pool = ThreadPoolBuilder::new()
            .with_size(AUTHORIZATION_THREAD_POOL_SIZE)
            .with_prefix("AuthorizationManager-".into())
            .build()
            .map_err(|err| AuthorizationManagerError(err.to_string()))?;

        let shared = Arc::new(Mutex::new(ManagedAuthorizations::new()));

        Ok(Self {
            local_identity,
            thread_pool,
            shared,
        })
    }

    pub fn shutdown_signaler(&self) -> ShutdownSignaler {
        ShutdownSignaler {
            thread_pool_signaler: self.thread_pool.shutdown_signaler(),
        }
    }

    pub fn wait_for_shutdown(self) {
        self.thread_pool.join_all()
    }

    pub fn authorization_connector(&self) -> AuthorizationConnector {
        AuthorizationConnector {
            local_identity: self.local_identity.clone(),
            shared: Arc::clone(&self.shared),
            executor: self.thread_pool.executor(),
        }
    }
}

pub struct ShutdownSignaler {
    thread_pool_signaler: pool::ShutdownSignaler,
}

impl ShutdownSignaler {
    pub fn shutdown(&self) {
        self.thread_pool_signaler.shutdown();
    }
}

type Callback =
    Box<dyn Fn(ConnectionAuthorizationState) -> Result<(), Box<dyn std::error::Error>> + Send>;

pub struct AuthorizationConnector {
    local_identity: String,
    shared: Arc<Mutex<ManagedAuthorizations>>,
    executor: pool::JobExecutor,
}

impl AuthorizationConnector {
    pub fn add_connection(
        &self,
        connection_id: String,
        connection: Box<dyn Connection>,
        on_complete_callback: Callback,
    ) -> Result<(), AuthorizationManagerError> {
        let mut connection = connection;

        let (tx, rx) = mpsc::channel();
        let connection_shared = Arc::clone(&self.shared);
        let state_machine = AuthorizationManagerStateMachine {
            shared: Arc::clone(&self.shared),
        };
        let msg_sender = AuthorizationMessageSender { sender: tx };
        let dispatcher =
            create_authorization_dispatcher(self.local_identity.clone(), state_machine, msg_sender);
        self.executor.execute(move || {
            #[cfg(not(feature = "trust-authorization"))]
            {
                let connect_request_bytes = match connect_msg_bytes() {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        error!(
                            "Unable to create connect request for {}; aborting auth: {}",
                            &connection_id, err
                        );
                        return;
                    }
                };
                if let Err(err) = connection.send(&connect_request_bytes) {
                    error!(
                        "Unable to send connect request to {}; aborting auth: {}",
                        &connection_id, err
                    );
                    return;
                }
            }

            #[cfg(feature = "trust-authorization")]
            {
                let protocol_request_bytes = match protocol_msg_bytes() {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        error!(
                            "Unable to create protocol request for {}; aborting auth: {}",
                            &connection_id, err
                        );
                        return;
                    }
                };
                if let Err(err) = connection.send(&protocol_request_bytes) {
                    error!(
                        "Unable to send protocol request to {}; aborting auth: {}",
                        &connection_id, err
                    );
                    return;
                }
            }

            let authed_identity = 'main: loop {
                match connection.recv() {
                    Ok(bytes) => {
                        let mut msg: NetworkMessage = match Message::parse_from_bytes(&bytes) {
                            Ok(msg) => msg,
                            Err(err) => {
                                warn!("Received invalid network message: {}", err);
                                continue;
                            }
                        };

                        let message_type = msg.get_message_type();
                        if let Err(err) = dispatcher.dispatch(
                            connection_id.clone().into(),
                            &message_type,
                            msg.take_payload(),
                        ) {
                            error!(
                                "Unable to dispatch message of type {:?}: {}",
                                message_type, err
                            );
                        }
                    }
                    Err(RecvError::Disconnected) => {
                        error!("Connection unexpectedly disconnected; aborting authorization");
                        break 'main None;
                    }
                    Err(RecvError::IoError(err)) => {
                        error!("Unable to authorize connection due to I/O error: {}", err);
                        break 'main None;
                    }
                    Err(RecvError::ProtocolError(msg)) => {
                        error!(
                            "Unable to authorize connection due to protocol error: {}",
                            msg
                        );
                        break 'main None;
                    }
                    Err(RecvError::WouldBlock) => continue,
                }

                while let Ok(outgoing) = rx.try_recv() {
                    match connection.send(&outgoing) {
                        Ok(()) => (),
                        Err(err) => {
                            error!("Unable to send outgoing message; aborting auth: {}", err);
                            break 'main None;
                        }
                    }
                }

                let mut shared = match connection_shared.lock() {
                    Ok(shared) => shared,
                    Err(_) => {
                        error!("connection authorization lock poisoned; aborting auth");
                        break 'main None;
                    }
                };

                if let Some(true) = shared.is_complete(&connection_id) {
                    break 'main shared.take_connection_identity(&connection_id);
                }
            };

            let auth_state = if let Some(identity) = authed_identity {
                ConnectionAuthorizationState::Authorized {
                    connection_id,
                    connection,
                    identity,
                }
            } else {
                ConnectionAuthorizationState::Unauthorized {
                    connection_id,
                    connection,
                }
            };

            if let Err(err) = on_complete_callback(auth_state) {
                error!("unable to pass auth result to callback: {}", err);
            }
        });

        Ok(())
    }
}

#[cfg(not(feature = "trust-authorization"))]
fn connect_msg_bytes() -> Result<Vec<u8>, AuthorizationManagerError> {
    let mut network_msg = NetworkMessage::new();
    network_msg.set_message_type(NetworkMessageType::AUTHORIZATION);

    let connect_msg = AuthorizationMessage::ConnectRequest(ConnectRequest::Bidirectional);
    network_msg.set_payload(
        IntoBytes::<authorization::AuthorizationMessage>::into_bytes(connect_msg).map_err(
            |err| AuthorizationManagerError(format!("Unable to send connect request: {}", err)),
        )?,
    );

    network_msg.write_to_bytes().map_err(|err| {
        AuthorizationManagerError(format!("Unable to send connect request: {}", err))
    })
}

#[cfg(feature = "trust-authorization")]
fn protocol_msg_bytes() -> Result<Vec<u8>, AuthorizationManagerError> {
    let mut network_msg = NetworkMessage::new();
    network_msg.set_message_type(NetworkMessageType::AUTHORIZATION);

    let connect_msg = AuthorizationMessage::AuthProtocolRequest(AuthProtocolRequest {
        auth_protocol_min: PEER_AUTHORIZATION_PROTOCOL_MIN,
        auth_protocol_max: PEER_AUTHORIZATION_PROTOCOL_VERSION,
    });
    network_msg.set_payload(
        IntoBytes::<authorization::AuthorizationMessage>::into_bytes(connect_msg).map_err(
            |err| AuthorizationManagerError(format!("Unable to send connect request: {}", err)),
        )?,
    );

    network_msg.write_to_bytes().map_err(|err| {
        AuthorizationManagerError(format!("Unable to send connect request: {}", err))
    })
}

#[derive(Clone)]
pub struct AuthorizationMessageSender {
    sender: mpsc::Sender<Vec<u8>>,
}

impl AuthorizationMessageSender {
    pub fn send(&self, msg: Vec<u8>) -> Result<(), Vec<u8>> {
        self.sender.send(msg).map_err(|err| err.0)
    }
}

#[derive(Clone, Default)]
pub struct AuthorizationManagerStateMachine {
    shared: Arc<Mutex<ManagedAuthorizations>>,
}

impl AuthorizationManagerStateMachine {
    /// Transitions from one authorization state to another
    ///
    /// Errors
    ///
    /// The errors are error messages that should be returned on the appropriate message
    pub(crate) fn next_state(
        &self,
        connection_id: &str,
        action: AuthorizationAction,
    ) -> Result<AuthorizationState, AuthorizationActionError> {
        let mut shared = self.shared.lock().map_err(|_| {
            AuthorizationActionError::InternalError("Authorization pool lock was poisoned".into())
        })?;

        let mut cur_state =
            shared
                .states
                .entry(connection_id.to_string())
                .or_insert(ManagedAuthorizationState {
                    state: AuthorizationState::Unknown,
                    remote_state: AuthorizationState::Unknown,
                });

        if action == AuthorizationAction::Unauthorizing {
            cur_state.state = AuthorizationState::Unauthorized;
            cur_state.remote_state = AuthorizationState::Unauthorized;
            return Ok(AuthorizationState::Unauthorized);
        }

        match &cur_state.state {
            AuthorizationState::Unknown => match action {
                AuthorizationAction::Connecting => {
                    cur_state.state = AuthorizationState::Connecting;
                    cur_state.remote_state = AuthorizationState::NotApplicable;
                    Ok(AuthorizationState::Connecting)
                }
                #[cfg(feature = "trust-authorization")]
                AuthorizationAction::ProtocolAgreeing => {
                    cur_state.state = AuthorizationState::ProtocolAgreeing;
                    Ok(AuthorizationState::ProtocolAgreeing)
                }
                _ => Err(AuthorizationActionError::InvalidMessageOrder(
                    AuthorizationState::Unknown,
                    action,
                )),
            },
            // v0 state transitions
            AuthorizationState::Connecting => match action {
                AuthorizationAction::Connecting => Err(AuthorizationActionError::AlreadyConnecting),
                AuthorizationAction::TrustIdentifyingV0(identity) => {
                    let new_state = AuthorizationState::RemoteIdentified(identity);
                    cur_state.state = new_state.clone();
                    // Verify pub key allowed
                    Ok(new_state)
                }
                AuthorizationAction::RemoteAuthorizing => {
                    cur_state.state = AuthorizationState::RemoteAccepted;
                    Ok(AuthorizationState::RemoteAccepted)
                }
                _ => Err(AuthorizationActionError::InvalidMessageOrder(
                    AuthorizationState::Connecting,
                    action,
                )),
            },
            AuthorizationState::RemoteIdentified(identity) => match action {
                AuthorizationAction::RemoteAuthorizing => {
                    let new_state = AuthorizationState::AuthComplete(identity.clone());
                    cur_state.state = new_state.clone();
                    Ok(new_state)
                }
                _ => Err(AuthorizationActionError::InvalidMessageOrder(
                    AuthorizationState::RemoteIdentified(identity.clone()),
                    action,
                )),
            },
            AuthorizationState::RemoteAccepted => match action {
                AuthorizationAction::TrustIdentifyingV0(identity) => {
                    let new_state = AuthorizationState::AuthComplete(identity);
                    cur_state.state = new_state.clone();
                    Ok(new_state)
                }
                _ => Err(AuthorizationActionError::InvalidMessageOrder(
                    AuthorizationState::RemoteAccepted,
                    action,
                )),
            },
            // v1 state transitions
            #[cfg(feature = "trust-authorization")]
            AuthorizationState::ProtocolAgreeing => match action {
                AuthorizationAction::TrustIdentifying(identity) => {
                    let new_state = AuthorizationState::TrustIdentified(identity);
                    cur_state.state = new_state.clone();
                    Ok(new_state)
                }
                _ => Err(AuthorizationActionError::InvalidMessageOrder(
                    AuthorizationState::RemoteAccepted,
                    action,
                )),
            },
            #[cfg(feature = "trust-authorization")]
            AuthorizationState::TrustIdentified(identity) => match action {
                AuthorizationAction::Authorizing => {
                    let new_state = {
                        match &cur_state.remote_state {
                            AuthorizationState::Authorized(local_id) => {
                                cur_state.remote_state =
                                    AuthorizationState::AuthComplete(local_id.to_string());
                                AuthorizationState::AuthComplete(identity.to_string())
                            }
                            _ => AuthorizationState::Authorized(identity.to_string()),
                        }
                    };

                    cur_state.state = new_state.clone();
                    Ok(new_state)
                }
                _ => Err(AuthorizationActionError::InvalidMessageOrder(
                    AuthorizationState::RemoteAccepted,
                    action,
                )),
            },
            _ => Err(AuthorizationActionError::InvalidMessageOrder(
                cur_state.state.clone(),
                action,
            )),
        }
    }

    /// Transitions from one authorization state to another. This is specific to the remote node
    ///
    /// Errors
    ///
    /// The errors are error messages that should be returned on the appropriate message
    #[cfg(feature = "trust-authorization")]
    pub(crate) fn next_remote_state(
        &self,
        connection_id: &str,
        action: AuthorizationAction,
    ) -> Result<AuthorizationState, AuthorizationActionError> {
        let mut shared = self.shared.lock().map_err(|_| {
            AuthorizationActionError::InternalError("Authorization pool lock was poisoned".into())
        })?;

        let mut cur_state =
            shared
                .states
                .entry(connection_id.to_string())
                .or_insert(ManagedAuthorizationState {
                    state: AuthorizationState::Unknown,
                    remote_state: AuthorizationState::Unknown,
                });

        if action == AuthorizationAction::Unauthorizing {
            cur_state.state = AuthorizationState::Unauthorized;
            cur_state.remote_state = AuthorizationState::Unauthorized;
            return Ok(AuthorizationState::Unauthorized);
        }

        match &cur_state.remote_state {
            AuthorizationState::Unknown => match action {
                AuthorizationAction::ProtocolAgreeing => {
                    cur_state.remote_state = AuthorizationState::ProtocolAgreeing;
                    Ok(AuthorizationState::ProtocolAgreeing)
                }
                _ => Err(AuthorizationActionError::InvalidMessageOrder(
                    AuthorizationState::Unknown,
                    action,
                )),
            },
            // v1 state transitions
            AuthorizationState::ProtocolAgreeing => match action {
                AuthorizationAction::TrustIdentifying(identity) => {
                    let new_state = AuthorizationState::TrustIdentified(identity);
                    cur_state.remote_state = new_state.clone();
                    Ok(new_state)
                }
                _ => Err(AuthorizationActionError::InvalidMessageOrder(
                    AuthorizationState::RemoteAccepted,
                    action,
                )),
            },
            AuthorizationState::TrustIdentified(identity) => match action {
                AuthorizationAction::Authorizing => {
                    let new_state = {
                        match &cur_state.state {
                            AuthorizationState::Authorized(local_id) => {
                                cur_state.state =
                                    AuthorizationState::AuthComplete(local_id.to_string());
                                AuthorizationState::AuthComplete(identity.to_string())
                            }
                            _ => AuthorizationState::Authorized(identity.to_string()),
                        }
                    };

                    cur_state.remote_state = new_state.clone();
                    Ok(new_state)
                }
                _ => Err(AuthorizationActionError::InvalidMessageOrder(
                    AuthorizationState::RemoteAccepted,
                    action,
                )),
            },
            _ => Err(AuthorizationActionError::InvalidMessageOrder(
                cur_state.remote_state.clone(),
                action,
            )),
        }
    }
}

#[derive(Default)]
struct ManagedAuthorizations {
    states: HashMap<String, ManagedAuthorizationState>,
}

impl ManagedAuthorizations {
    fn new() -> Self {
        Self {
            states: HashMap::new(),
        }
    }

    fn take_connection_identity(&mut self, connection_id: &str) -> Option<String> {
        self.states.remove(connection_id).and_then(|managed_state| {
            match managed_state.remote_state {
                AuthorizationState::AuthComplete(identity) => Some(identity),
                AuthorizationState::NotApplicable => match managed_state.state {
                    AuthorizationState::AuthComplete(identity) => Some(identity),
                    _ => None,
                },
                _ => None,
            }
        })
    }

    fn is_complete(&self, connection_id: &str) -> Option<bool> {
        self.states.get(connection_id).map(|managed_state| {
            matches!(
                (&managed_state.state, &managed_state.remote_state),
                (
                    AuthorizationState::AuthComplete(_),
                    AuthorizationState::AuthComplete(_)
                ) | (
                    AuthorizationState::AuthComplete(_),
                    AuthorizationState::NotApplicable
                ) | (
                    AuthorizationState::Unauthorized,
                    AuthorizationState::Unauthorized
                )
            )
        })
    }
}

pub enum ConnectionAuthorizationState {
    Authorized {
        connection_id: String,
        identity: String,
        connection: Box<dyn Connection>,
    },
    Unauthorized {
        connection_id: String,
        connection: Box<dyn Connection>,
    },
}

impl std::fmt::Debug for ConnectionAuthorizationState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ConnectionAuthorizationState::Authorized {
                connection_id,
                identity,
                ..
            } => f
                .debug_struct("Authorized")
                .field("connection_id", connection_id)
                .field("identity", identity)
                .finish(),
            ConnectionAuthorizationState::Unauthorized { connection_id, .. } => f
                .debug_struct("Unauthorized")
                .field("connection_id", connection_id)
                .finish(),
        }
    }
}

#[cfg(test)]
pub(in crate::network) mod tests {
    use super::*;

    use protobuf::Message;

    use crate::mesh::{Envelope, Mesh};
    #[cfg(feature = "trust-authorization")]
    use crate::protocol::authorization::{
        AuthComplete, AuthProtocolRequest, AuthProtocolResponse, AuthTrustRequest,
        AuthTrustResponse, AuthorizationMessage, PeerAuthorizationType,
    };
    #[cfg(not(feature = "trust-authorization"))]
    use crate::protocol::authorization::{
        AuthorizationMessage, AuthorizationType, Authorized, ConnectRequest, ConnectResponse,
        TrustRequest,
    };
    use crate::protos::authorization;
    use crate::protos::network::{NetworkMessage, NetworkMessageType};

    impl AuthorizationManager {
        /// A test friendly shutdown and wait method.
        pub fn shutdown_and_await(self) {
            self.shutdown_signaler().shutdown();
            self.wait_for_shutdown();
        }
    }

    #[cfg(not(feature = "trust-authorization"))]
    pub(in crate::network) fn negotiation_connection_auth(
        mesh: &Mesh,
        connection_id: &str,
        expected_identity: &str,
    ) {
        let env = mesh.recv().expect("unable to receive from mesh");

        // receive the connect request from the connection manager
        assert_eq!(connection_id, env.id());
        let connect_request = read_auth_message(env.payload());
        assert!(matches!(
            connect_request,
            AuthorizationMessage::ConnectRequest(ConnectRequest::Bidirectional)
        ));

        // send our own connect request
        let env = write_auth_message(
            connection_id,
            AuthorizationMessage::ConnectRequest(ConnectRequest::Unidirectional),
        );
        mesh.send(env).expect("Unable to send connect response");

        let env = write_auth_message(
            connection_id,
            AuthorizationMessage::ConnectResponse(ConnectResponse {
                accepted_authorization_types: vec![AuthorizationType::Trust],
            }),
        );
        mesh.send(env).expect("Unable to send connect response");

        // receive the connect response
        let env = mesh.recv().expect("unable to receive from mesh");
        assert_eq!(connection_id, env.id());
        let connect_response = read_auth_message(env.payload());
        assert!(matches!(
            connect_response,
            AuthorizationMessage::ConnectResponse(_)
        ));

        // receive the trust request
        let env = mesh.recv().expect("unable to receive from mesh");
        assert_eq!(connection_id, env.id());
        let trust_request = read_auth_message(env.payload());
        assert!(matches!(
            trust_request,
            AuthorizationMessage::TrustRequest(TrustRequest { .. })
        ));

        // send authorized
        let env = write_auth_message(connection_id, AuthorizationMessage::Authorized(Authorized));
        mesh.send(env).expect("unable to send authorized");

        // send trust request
        let env = write_auth_message(
            connection_id,
            AuthorizationMessage::TrustRequest(TrustRequest {
                identity: expected_identity.to_string(),
            }),
        );
        mesh.send(env).expect("unable to send authorized");

        // receive authorized
        let env = mesh.recv().expect("unable to receive from mesh");
        assert_eq!(connection_id, env.id());
        let trust_request = read_auth_message(env.payload());
        assert!(matches!(trust_request, AuthorizationMessage::Authorized(_)));
    }

    #[cfg(feature = "trust-authorization")]
    pub(in crate::network) fn negotiation_connection_auth(
        mesh: &Mesh,
        connection_id: &str,
        expected_identity: &str,
    ) {
        let env = mesh.recv().expect("unable to receive from mesh");

        // receive the protocol request from the connection manager
        assert_eq!(connection_id, env.id());
        let connect_request = read_auth_message(env.payload());
        assert!(matches!(
            connect_request,
            AuthorizationMessage::AuthProtocolRequest(_)
        ));

        // send our own protocol_request
        let env = write_auth_message(
            connection_id,
            AuthorizationMessage::AuthProtocolRequest(AuthProtocolRequest {
                auth_protocol_min: PEER_AUTHORIZATION_PROTOCOL_MIN,
                auth_protocol_max: PEER_AUTHORIZATION_PROTOCOL_VERSION,
            }),
        );
        mesh.send(env).expect("Unable to send protocol request");

        let env = write_auth_message(
            connection_id,
            AuthorizationMessage::AuthProtocolResponse(AuthProtocolResponse {
                auth_protocol: PEER_AUTHORIZATION_PROTOCOL_VERSION,
                accepted_authorization_type: vec![PeerAuthorizationType::Trust],
            }),
        );
        mesh.send(env).expect("Unable to send protocol request");

        // receive the protocol response
        let env = mesh.recv().expect("unable to receive from mesh");
        assert_eq!(connection_id, env.id());
        let protocol_response = read_auth_message(env.payload());
        assert!(matches!(
            protocol_response,
            AuthorizationMessage::AuthProtocolResponse(_)
        ));

        // receive the trust request
        let env = mesh.recv().expect("unable to receive from mesh");
        assert_eq!(connection_id, env.id());
        let trust_request = read_auth_message(env.payload());
        assert!(matches!(
            trust_request,
            AuthorizationMessage::AuthTrustRequest(AuthTrustRequest { .. })
        ));

        // send trust response
        let env = write_auth_message(
            connection_id,
            AuthorizationMessage::AuthTrustResponse(AuthTrustResponse),
        );
        mesh.send(env).expect("unable to send authorized");

        // send auth complete
        let env = write_auth_message(
            connection_id,
            AuthorizationMessage::AuthComplete(AuthComplete),
        );
        mesh.send(env).expect("unable to send authorized");

        // send trust request
        let env = write_auth_message(
            connection_id,
            AuthorizationMessage::AuthTrustRequest(AuthTrustRequest {
                identity: expected_identity.to_string(),
            }),
        );
        mesh.send(env).expect("unable to send authorized");

        // receive authorized
        let env = mesh.recv().expect("unable to receive from mesh");
        assert_eq!(connection_id, env.id());
        let trust_response = read_auth_message(env.payload());
        assert!(matches!(
            trust_response,
            AuthorizationMessage::AuthTrustResponse(_)
        ));

        // receive authorized
        let env = mesh.recv().expect("unable to receive from mesh");
        assert_eq!(connection_id, env.id());
        let auth_complete = read_auth_message(env.payload());
        assert!(matches!(
            auth_complete,
            AuthorizationMessage::AuthComplete(_)
        ));
    }

    fn read_auth_message(bytes: &[u8]) -> AuthorizationMessage {
        let msg: NetworkMessage =
            Message::parse_from_bytes(bytes).expect("Cannot parse network message");

        assert_eq!(NetworkMessageType::AUTHORIZATION, msg.get_message_type());

        FromBytes::<authorization::AuthorizationMessage>::from_bytes(msg.get_payload())
            .expect("Unable to parse bytes")
    }

    fn write_auth_message(connection_id: &str, auth_msg: AuthorizationMessage) -> Envelope {
        let mut msg = NetworkMessage::new();
        msg.set_message_type(NetworkMessageType::AUTHORIZATION);
        msg.set_payload(
            IntoBytes::<authorization::AuthorizationMessage>::into_bytes(auth_msg)
                .expect("Unable to convert into bytes"),
        );

        Envelope::new(
            connection_id.to_string(),
            msg.write_to_bytes().expect("Unable to write to bytes"),
        )
    }
}
