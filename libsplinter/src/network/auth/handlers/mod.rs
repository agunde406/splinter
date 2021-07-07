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

//! Message handlers for authorization messages

mod v0_handlers;
#[cfg(any(feature = "trust-authorization", feature = "challenge-authorization"))]
mod v1_handlers;

#[cfg(feature = "challenge-authorization")]
use cylinder::{Signer, Verifier};

use crate::error::InvalidStateError;
#[cfg(feature = "challenge-authorization")]
use crate::network::auth::ConnectionAuthorizationType;
use crate::network::auth::{
    AuthorizationManagerStateMachine, AuthorizationMessageSender, AuthorizationRemoteAction,
    AuthorizationRemoteState,
};
use crate::network::dispatch::{
    ConnectionId, DispatchError, Dispatcher, Handler, MessageContext, MessageSender,
};
use crate::protocol::authorization::AuthorizationError;
use crate::protos::authorization;
use crate::protos::network::NetworkMessageType;
use crate::protos::prelude::*;

use self::v0_handlers::{
    AuthorizedHandler, ConnectRequestHandler, ConnectResponseHandler, TrustRequestHandler,
};
#[cfg(feature = "challenge-authorization")]
use self::v1_handlers::{
    AuthChallengeNonceRequestHandler, AuthChallengeNonceResponseHandler,
    AuthChallengeSubmitRequestHandler, AuthChallengeSubmitResponseHandler,
};
#[cfg(any(feature = "trust-authorization", feature = "challenge-authorization"))]
use self::v1_handlers::{
    AuthCompleteHandler, AuthProtocolRequestHandler, AuthProtocolResponseHandler,
};
#[cfg(feature = "trust-authorization")]
use self::v1_handlers::{AuthTrustRequestHandler, AuthTrustResponseHandler};

/// Create a Dispatcher for Authorization messages
///
/// Creates and configures a Dispatcher to handle messages from an AuthorizationMessage envelope.
/// The dispatcher is provided the given network sender for response messages, and the network
/// itself to handle updating identities (or removing connections with authorization failures).
///
/// The identity provided is sent to connections for Trust authorizations.
#[allow(clippy::too_many_arguments)]
pub fn create_authorization_dispatcher(
    identity: String,
    #[cfg(feature = "challenge-authorization")] signers: Vec<Box<dyn Signer>>,
    auth_manager: AuthorizationManagerStateMachine,
    auth_msg_sender: impl MessageSender<ConnectionId> + Clone + 'static,
    #[cfg(feature = "challenge-authorization")] nonce: Vec<u8>,
    #[cfg(feature = "challenge-authorization")] expected_authorization: Option<
        ConnectionAuthorizationType,
    >,
    #[cfg(feature = "challenge-authorization")] local_authorization: Option<
        ConnectionAuthorizationType,
    >,
    #[cfg(feature = "challenge-authorization")] verifer: Box<dyn Verifier>,
) -> Result<Dispatcher<NetworkMessageType, ConnectionId>, InvalidStateError> {
    let mut auth_dispatcher = Dispatcher::new(Box::new(auth_msg_sender.clone()));

    // v0 message handlers
    auth_dispatcher.set_handler(Box::new(ConnectRequestHandler::new(auth_manager.clone())));

    // allow redundant_clone, must be cloned here if trust-authorization is enabled
    #[allow(clippy::redundant_clone)]
    auth_dispatcher.set_handler(Box::new(ConnectResponseHandler::new(identity.to_string())));

    auth_dispatcher.set_handler(Box::new(TrustRequestHandler::new(auth_manager.clone())));

    auth_dispatcher.set_handler(Box::new(AuthorizedHandler::new(auth_manager.clone())));

    auth_dispatcher.set_handler(Box::new(AuthorizedHandler::new(auth_manager.clone())));

    // v1 message handlers
    #[cfg(any(feature = "trust-authorization", feature = "challenge-authorization"))]
    {
        auth_dispatcher.set_handler(Box::new(AuthProtocolRequestHandler::new(
            auth_manager.clone(),
        )));

        auth_dispatcher.set_handler(Box::new(AuthProtocolResponseHandler::new(
            auth_manager.clone(),
            #[cfg(feature = "trust-authorization")]
            identity,
            #[cfg(feature = "challenge-authorization")]
            local_authorization.clone(),
            #[cfg(not(feature = "challenge-authorization"))]
            None,
        )));

        auth_dispatcher.set_handler(Box::new(AuthCompleteHandler::new(auth_manager.clone())));
    }

    #[cfg(feature = "trust-authorization")]
    {
        auth_dispatcher.set_handler(Box::new(AuthTrustRequestHandler::new(auth_manager.clone())));

        auth_dispatcher.set_handler(Box::new(AuthTrustResponseHandler::new(
            auth_manager.clone(),
        )));
    }

    // If no signers are configured do not configure challenge authorization
    #[cfg(feature = "challenge-authorization")]
    if !signers.is_empty() {
        auth_dispatcher.set_handler(Box::new(AuthChallengeNonceRequestHandler::new(
            auth_manager.clone(),
            nonce.clone(),
        )));

        let signers_to_use = match &local_authorization {
            Some(ConnectionAuthorizationType::Challenge { public_key }) => {
                let signer = signers.iter().find(|signer| match signer.public_key() {
                    Ok(signer_public_key) => signer_public_key.as_slice() == public_key,
                    Err(_) => false,
                });

                match signer {
                    Some(signer) => vec![signer.clone()],
                    None => {
                        return Err(InvalidStateError::with_message(
                            "Required local authorization is not supported".to_string(),
                        ));
                    }
                }
            }

            // if there is no local_authorization which key is used here does not matter
            _ => signers.clone(),
        };

        auth_dispatcher.set_handler(Box::new(AuthChallengeNonceResponseHandler::new(
            auth_manager.clone(),
            signers_to_use,
        )));

        let expected_public_key = match expected_authorization {
            Some(ConnectionAuthorizationType::Challenge { public_key }) => Some(public_key),
            _ => None,
        };

        auth_dispatcher.set_handler(Box::new(AuthChallengeSubmitRequestHandler::new(
            auth_manager.clone(),
            verifer,
            nonce,
            expected_public_key,
        )));

        auth_dispatcher.set_handler(Box::new(AuthChallengeSubmitResponseHandler::new(
            auth_manager.clone(),
        )));
    }

    auth_dispatcher.set_handler(Box::new(AuthorizationErrorHandler::new(auth_manager)));

    let mut network_msg_dispatcher = Dispatcher::new(Box::new(auth_msg_sender));

    network_msg_dispatcher.set_handler(Box::new(AuthorizationMessageHandler::new(auth_dispatcher)));

    Ok(network_msg_dispatcher)
}

/// The Handler for authorization network messages.
///
/// This Handler accepts authorization network messages, unwraps the envelope, and forwards the
/// message contents to an authorization dispatcher.
pub struct AuthorizationMessageHandler {
    auth_dispatcher: Dispatcher<authorization::AuthorizationMessageType, ConnectionId>,
}

impl AuthorizationMessageHandler {
    /// Constructs a new AuthorizationMessageHandler
    ///
    /// This constructs an AuthorizationMessageHandler with a sender that will dispatch messages
    /// to a authorization dispatcher.
    pub fn new(
        auth_dispatcher: Dispatcher<authorization::AuthorizationMessageType, ConnectionId>,
    ) -> Self {
        AuthorizationMessageHandler { auth_dispatcher }
    }
}

impl Handler for AuthorizationMessageHandler {
    type Source = ConnectionId;
    type MessageType = NetworkMessageType;
    type Message = authorization::AuthorizationMessage;

    fn match_type(&self) -> Self::MessageType {
        NetworkMessageType::AUTHORIZATION
    }

    fn handle(
        &self,
        mut msg: Self::Message,
        context: &MessageContext<Self::Source, Self::MessageType>,
        _sender: &dyn MessageSender<Self::Source>,
    ) -> Result<(), DispatchError> {
        let msg_type = msg.get_message_type();
        let payload = msg.take_payload();
        self.auth_dispatcher
            .dispatch(context.source_id().clone(), &msg_type, payload)
    }
}

/// Handler for the Authorization Error Message Type
pub struct AuthorizationErrorHandler {
    auth_manager: AuthorizationManagerStateMachine,
}

impl AuthorizationErrorHandler {
    pub fn new(auth_manager: AuthorizationManagerStateMachine) -> Self {
        AuthorizationErrorHandler { auth_manager }
    }
}

impl Handler for AuthorizationErrorHandler {
    type Source = ConnectionId;
    type MessageType = authorization::AuthorizationMessageType;
    type Message = authorization::AuthorizationError;

    fn match_type(&self) -> Self::MessageType {
        authorization::AuthorizationMessageType::AUTHORIZATION_ERROR
    }

    fn handle(
        &self,
        msg: Self::Message,
        context: &MessageContext<Self::Source, Self::MessageType>,
        _: &dyn MessageSender<Self::Source>,
    ) -> Result<(), DispatchError> {
        let auth_error = AuthorizationError::from_proto(msg)?;
        match auth_error {
            AuthorizationError::AuthorizationRejected(err_msg) => {
                match self.auth_manager.next_remote_state(
                    context.source_connection_id(),
                    AuthorizationRemoteAction::Unauthorizing,
                ) {
                    Ok(AuthorizationRemoteState::Unauthorized) => {
                        info!(
                            "Connection unauthorized by connection {}: {}",
                            context.source_connection_id(),
                            &err_msg
                        );
                    }
                    Err(err) => {
                        warn!(
                            "Unable to handle unauthorizing by connection {}: {}",
                            context.source_connection_id(),
                            err
                        );
                    }
                    Ok(next_state) => {
                        panic!("Should not have been able to transition to {}", next_state)
                    }
                }
            }
        }
        Ok(())
    }
}

impl MessageSender<ConnectionId> for AuthorizationMessageSender {
    fn send(&self, id: ConnectionId, message: Vec<u8>) -> Result<(), (ConnectionId, Vec<u8>)> {
        AuthorizationMessageSender::send(self, message).map_err(|msg| (id, msg))
    }
}
