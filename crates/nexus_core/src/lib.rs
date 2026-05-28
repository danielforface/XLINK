use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU8, Ordering};
use thiserror::Error;

const SESSION_ID_RANDOM_BYTES: usize = 6;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionState {
    Unauthenticated,
    Authenticating,
    PendingConsent,
    Active,
    Rejected,
    Terminated,
}

impl SessionState {
    fn as_u8(self) -> u8 {
        match self {
            SessionState::Unauthenticated => 0,
            SessionState::Authenticating => 1,
            SessionState::PendingConsent => 2,
            SessionState::Active => 3,
            SessionState::Rejected => 4,
            SessionState::Terminated => 5,
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => SessionState::Authenticating,
            2 => SessionState::PendingConsent,
            3 => SessionState::Active,
            4 => SessionState::Rejected,
            5 => SessionState::Terminated,
            _ => SessionState::Unauthenticated,
        }
    }
}

#[derive(Debug)]
pub struct SessionStateMachine {
    state: AtomicU8,
}

impl Default for SessionStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStateMachine {
    pub fn new() -> Self {
        Self {
            state: AtomicU8::new(SessionState::Unauthenticated.as_u8()),
        }
    }

    pub fn state(&self) -> SessionState {
        SessionState::from_u8(self.state.load(Ordering::Acquire))
    }

    pub fn is_active(&self) -> bool {
        self.state() == SessionState::Active
    }

    pub fn transition(&self, next: SessionState) -> Result<(), SecurityError> {
        loop {
            let current_raw = self.state.load(Ordering::Acquire);
            let current = SessionState::from_u8(current_raw);

            if !is_transition_allowed(current, next) {
                return Err(SecurityError::InvalidStateTransition {
                    from: current,
                    to: next,
                });
            }

            match self.state.compare_exchange(
                current_raw,
                next.as_u8(),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(_) => continue,
            }
        }
    }
}

fn is_transition_allowed(from: SessionState, to: SessionState) -> bool {
    if from == to {
        return true;
    }

    matches!(
        (from, to),
        (SessionState::Unauthenticated, SessionState::Authenticating)
            | (SessionState::Authenticating, SessionState::PendingConsent)
            | (SessionState::Authenticating, SessionState::Rejected)
            | (SessionState::Authenticating, SessionState::Terminated)
            | (SessionState::PendingConsent, SessionState::Active)
            | (SessionState::PendingConsent, SessionState::Rejected)
            | (SessionState::PendingConsent, SessionState::Terminated)
            | (SessionState::Active, SessionState::Terminated)
            | (SessionState::Rejected, SessionState::Terminated)
    )
}

#[derive(Debug, Clone)]
pub struct SessionCredentials {
    pub session_id: String,
}

impl SessionCredentials {
    pub fn generate() -> Self {
        let mut rng = OsRng;

        let mut session_id_bytes = [0_u8; SESSION_ID_RANDOM_BYTES];
        rng.fill_bytes(&mut session_id_bytes);
        let session_id = hex::encode(session_id_bytes);

        Self { session_id }
    }

    pub fn verify(&self, target_id: &str) -> Result<(), SecurityError> {
        let id_matches = constant_time_equals(target_id.as_bytes(), self.session_id.as_bytes());

        if id_matches {
            Ok(())
        } else {
            Err(SecurityError::AuthenticationFailed)
        }
    }
}

fn constant_time_equals(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();

    for index in 0..max_len {
        let lhs = *left.get(index).unwrap_or(&0);
        let rhs = *right.get(index).unwrap_or(&0);
        diff |= (lhs ^ rhs) as usize;
    }

    diff == 0
}

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("local user denied consent")]
    UserConsentDenied,
    #[error("invalid session state transition: {from:?} -> {to:?}")]
    InvalidStateTransition { from: SessionState, to: SessionState },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlMessage {
    Hello { role: String, protocol_version: u16 },
    AuthRequest {
        requester_id: String,
        target_id: String,
    },
    AuthResult { success: bool, message: String },
    AccessRequest {
        session_id: String,
    },
    AccessDecision {
        approved: bool,
    },
    SessionConsent { approved: bool },
    SimulatedMouseMove { x_norm: f32, y_norm: f32 },
    SimulatedKeyEvent { virtual_key: u16, pressed: bool },
    Ack(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FramePacket {
    pub sequence: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub pixels: Vec<u8>,
}

impl FramePacket {
    pub fn expected_buffer_len(&self) -> usize {
        self.checked_buffer_len().unwrap_or(usize::MAX)
    }

    pub fn checked_buffer_len(&self) -> Option<usize> {
        (self.stride as usize).checked_mul(self.height as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        constant_time_equals, ControlMessage, FramePacket, SecurityError, SessionCredentials,
        SessionState, SessionStateMachine,
    };

    #[test]
    fn frame_packet_checked_buffer_len_handles_overflow() {
        let packet = FramePacket {
            sequence: 0,
            width: u32::MAX,
            height: u32::MAX,
            stride: u32::MAX,
            pixels: Vec::new(),
        };

        if usize::BITS >= 64 {
            assert!(packet.checked_buffer_len().is_some());
        } else {
            assert!(packet.checked_buffer_len().is_none());
        }
    }

    #[test]
    fn control_message_roundtrip() {
        let original = ControlMessage::AuthRequest {
            requester_id: "requester".to_string(),
            target_id: "target".to_string(),
        };

        let encoded = bincode::serialize(&original).expect("serialize ControlMessage");
        let decoded: ControlMessage = bincode::deserialize(&encoded).expect("deserialize ControlMessage");

        match decoded {
            ControlMessage::AuthRequest {
                requester_id,
                target_id,
            } => {
                assert_eq!(requester_id, "requester");
                assert_eq!(target_id, "target");
            }
            other => panic!("unexpected control message variant: {other:?}"),
        }
    }

    #[test]
    fn state_machine_allows_expected_transition_path() {
        let state_machine = SessionStateMachine::new();
        assert_eq!(state_machine.state(), SessionState::Unauthenticated);

        state_machine
            .transition(SessionState::Authenticating)
            .expect("Unauthenticated -> Authenticating");
        state_machine
            .transition(SessionState::PendingConsent)
            .expect("Authenticating -> PendingConsent");
        state_machine
            .transition(SessionState::Active)
            .expect("PendingConsent -> Active");
        state_machine
            .transition(SessionState::Terminated)
            .expect("Active -> Terminated");
        assert_eq!(state_machine.state(), SessionState::Terminated);
    }

    #[test]
    fn state_machine_rejects_invalid_transition() {
        let state_machine = SessionStateMachine::new();
        let error = state_machine
            .transition(SessionState::Active)
            .expect_err("Unauthenticated -> Active must fail");

        match error {
            SecurityError::InvalidStateTransition { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn credential_verification_uses_expected_values() {
        let credentials = SessionCredentials {
            session_id: "abc12345".to_string(),
        };

        credentials
            .verify("abc12345")
            .expect("matching session id should pass");
        assert!(matches!(
            credentials.verify("wrong-target"),
            Err(SecurityError::AuthenticationFailed)
        ));
    }

    #[test]
    fn constant_time_compare_handles_length_mismatch() {
        assert!(!constant_time_equals(b"short", b"longer"));
        assert!(constant_time_equals(b"same", b"same"));
    }
}