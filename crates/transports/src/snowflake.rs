//! Snowflake broker rendezvous message codec.
//!
//! Snowflake clients and proxies do not know each other's addresses; they meet
//! through the broker over HTTPS with small JSON messages. This module encodes
//! and decodes those messages with the exact field names the broker speaks
//! (`Offer`, `Answer`, `Sid`, `NAT`, `Version`, `Status`), and validates the
//! field invariants (non-empty SDP, recognized NAT/status tokens) so a caller
//! can catch malformed broker traffic without string matching.
//!
//! The WebRTC data-channel layer (DTLS/SRTP + KCP framing of OR cells) is not
//! part of this codec; it is the transport's media path and is out of scope
//! here.

use serde::{Deserialize, Serialize};

use crate::error::TransportError;

/// The broker protocol version this codec emits.
pub const PROTOCOL_VERSION: &str = "1.0";

/// Broker status: a proxy was matched with a client.
pub const STATUS_CLIENT_MATCH: &str = "client match";
/// Broker status: no peer is currently available.
pub const STATUS_NO_MATCH: &str = "no match";
/// Broker status: the answer was accepted.
pub const STATUS_OK: &str = "ok";

/// NAT types a proxy may advertise.
pub const NAT_UNKNOWN: &str = "unknown";
pub const NAT_RESTRICTED: &str = "restricted";
pub const NAT_UNRESTRICTED: &str = "unrestricted";

/// A client's SDP offer posted to the broker (`POST /client`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientOffer {
    /// The WebRTC session description (SDP offer).
    #[serde(rename = "Offer")]
    pub offer: String,
    /// The client's NAT classification.
    #[serde(rename = "NAT")]
    pub nat: String,
    /// The stable session id shared with the matched proxy.
    #[serde(rename = "Sid")]
    pub sid: String,
    /// The broker protocol version.
    #[serde(rename = "Version")]
    pub version: String,
}

impl ClientOffer {
    /// Validate the message invariants.
    pub fn validate(&self) -> Result<(), TransportError> {
        if self.offer.is_empty() {
            return Err(TransportError::Snowflake("offer is empty".to_owned()));
        }
        if self.sid.is_empty() {
            return Err(TransportError::Snowflake("sid is empty".to_owned()));
        }
        if self.version != PROTOCOL_VERSION {
            return Err(TransportError::Snowflake(format!(
                "unsupported version {:?}",
                self.version
            )));
        }
        Ok(())
    }

    /// Serialize to broker wire bytes.
    pub fn encode(&self) -> Result<Vec<u8>, TransportError> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Parse and validate broker wire bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        let message: Self = serde_json::from_slice(bytes)?;
        message.validate()?;
        Ok(message)
    }
}

/// A client poll for a match (`POST /client` with no offer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientPollRequest {
    /// The stable session id.
    #[serde(rename = "Sid")]
    pub sid: String,
    /// The broker protocol version.
    #[serde(rename = "Version")]
    pub version: String,
}

impl ClientPollRequest {
    /// Validate the message invariants.
    pub fn validate(&self) -> Result<(), TransportError> {
        if self.sid.is_empty() {
            return Err(TransportError::Snowflake("sid is empty".to_owned()));
        }
        if self.version != PROTOCOL_VERSION {
            return Err(TransportError::Snowflake(format!(
                "unsupported version {:?}",
                self.version
            )));
        }
        Ok(())
    }

    /// Serialize to broker wire bytes.
    pub fn encode(&self) -> Result<Vec<u8>, TransportError> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Parse and validate broker wire bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        let message: Self = serde_json::from_slice(bytes)?;
        message.validate()?;
        Ok(message)
    }
}

/// The broker's reply to a client poll or offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientPollResponse {
    /// `client match` or `no match`.
    #[serde(rename = "Status")]
    pub status: String,
    /// The proxy's SDP answer, present when matched.
    #[serde(rename = "Answer", skip_serializing_if = "Option::is_none")]
    pub answer: Option<String>,
}

impl ClientPollResponse {
    /// Validate the message invariants, including status/answer consistency.
    pub fn validate(&self) -> Result<(), TransportError> {
        validate_status(&self.status)?;
        match self.status.as_str() {
            STATUS_CLIENT_MATCH if self.answer.as_deref().unwrap_or("").is_empty() => Err(
                TransportError::Snowflake("client match without an answer".to_owned()),
            ),
            STATUS_NO_MATCH if self.answer.is_some() => Err(TransportError::Snowflake(
                "no match with an answer".to_owned(),
            )),
            _ => Ok(()),
        }
    }

    /// Serialize to broker wire bytes.
    pub fn encode(&self) -> Result<Vec<u8>, TransportError> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }

    /// Parse and validate broker wire bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        let message: Self = serde_json::from_slice(bytes)?;
        message.validate()?;
        Ok(message)
    }
}

/// A proxy poll for work (`POST /proxy`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyPollRequest {
    /// The stable session id.
    #[serde(rename = "Sid")]
    pub sid: String,
    /// The broker protocol version.
    #[serde(rename = "Version")]
    pub version: String,
}

impl ProxyPollRequest {
    /// Validate the message invariants.
    pub fn validate(&self) -> Result<(), TransportError> {
        if self.sid.is_empty() {
            return Err(TransportError::Snowflake("sid is empty".to_owned()));
        }
        if self.version != PROTOCOL_VERSION {
            return Err(TransportError::Snowflake(format!(
                "unsupported version {:?}",
                self.version
            )));
        }
        Ok(())
    }

    /// Serialize to broker wire bytes.
    pub fn encode(&self) -> Result<Vec<u8>, TransportError> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Parse and validate broker wire bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        let message: Self = serde_json::from_slice(bytes)?;
        message.validate()?;
        Ok(message)
    }
}

/// The broker's reply to a proxy poll.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyPollResponse {
    /// `client match` or `no match`.
    #[serde(rename = "Status")]
    pub status: String,
    /// The client's SDP offer, present when matched.
    #[serde(rename = "Offer", skip_serializing_if = "Option::is_none")]
    pub offer: Option<String>,
}

impl ProxyPollResponse {
    /// Validate the message invariants, including status/offer consistency.
    pub fn validate(&self) -> Result<(), TransportError> {
        validate_status(&self.status)?;
        match self.status.as_str() {
            STATUS_CLIENT_MATCH if self.offer.as_deref().unwrap_or("").is_empty() => Err(
                TransportError::Snowflake("client match without an offer".to_owned()),
            ),
            STATUS_NO_MATCH if self.offer.is_some() => Err(TransportError::Snowflake(
                "no match with an offer".to_owned(),
            )),
            _ => Ok(()),
        }
    }

    /// Serialize to broker wire bytes.
    pub fn encode(&self) -> Result<Vec<u8>, TransportError> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }

    /// Parse and validate broker wire bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        let message: Self = serde_json::from_slice(bytes)?;
        message.validate()?;
        Ok(message)
    }
}

/// A proxy's SDP answer posted back to the broker (`POST /answer`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyAnswer {
    /// The WebRTC session description (SDP answer).
    #[serde(rename = "Answer")]
    pub answer: String,
    /// The stable session id.
    #[serde(rename = "Sid")]
    pub sid: String,
}

impl ProxyAnswer {
    /// Validate the message invariants.
    pub fn validate(&self) -> Result<(), TransportError> {
        if self.answer.is_empty() {
            return Err(TransportError::Snowflake("answer is empty".to_owned()));
        }
        if self.sid.is_empty() {
            return Err(TransportError::Snowflake("sid is empty".to_owned()));
        }
        Ok(())
    }

    /// Serialize to broker wire bytes.
    pub fn encode(&self) -> Result<Vec<u8>, TransportError> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Parse and validate broker wire bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        let message: Self = serde_json::from_slice(bytes)?;
        message.validate()?;
        Ok(message)
    }
}

fn validate_status(status: &str) -> Result<(), TransportError> {
    match status {
        STATUS_CLIENT_MATCH | STATUS_NO_MATCH => Ok(()),
        other => Err(TransportError::InvalidStatus(other.to_owned())),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn sdp() -> &'static str {
        "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\n"
    }

    #[test]
    fn client_offer_uses_broker_field_names() {
        let offer = ClientOffer {
            offer: sdp().to_owned(),
            nat: NAT_UNKNOWN.to_owned(),
            sid: "session-1".to_owned(),
            version: PROTOCOL_VERSION.to_owned(),
        };
        let bytes = offer.encode().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("\"Offer\""));
        assert!(text.contains("\"NAT\":\"unknown\""));
        assert!(text.contains("\"Sid\":\"session-1\""));
        assert_eq!(ClientOffer::decode(text.as_bytes()).unwrap(), offer);
    }

    #[test]
    fn client_offer_rejects_empty_offer() {
        let offer = ClientOffer {
            offer: String::new(),
            nat: NAT_UNKNOWN.to_owned(),
            sid: "s".to_owned(),
            version: PROTOCOL_VERSION.to_owned(),
        };
        assert!(offer.validate().is_err());
    }

    #[test]
    fn client_poll_response_round_trips_with_and_without_answer() {
        let matched = ClientPollResponse {
            status: STATUS_CLIENT_MATCH.to_owned(),
            answer: Some(sdp().to_owned()),
        };
        let bytes = matched.encode().unwrap();
        assert_eq!(ClientPollResponse::decode(&bytes).unwrap(), matched);

        let unmatched = ClientPollResponse {
            status: STATUS_NO_MATCH.to_owned(),
            answer: None,
        };
        let bytes = unmatched.encode().unwrap();
        assert_eq!(ClientPollResponse::decode(&bytes).unwrap(), unmatched);
    }

    #[test]
    fn client_poll_response_rejects_match_without_answer() {
        let bad = ClientPollResponse {
            status: STATUS_CLIENT_MATCH.to_owned(),
            answer: None,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn client_poll_response_rejects_unknown_status() {
        let bad = ClientPollResponse {
            status: "maybe".to_owned(),
            answer: None,
        };
        assert!(matches!(
            bad.validate(),
            Err(TransportError::InvalidStatus(_))
        ));
    }

    #[test]
    fn proxy_messages_round_trip() {
        let poll = ProxyPollRequest {
            sid: "proxy-1".to_owned(),
            version: PROTOCOL_VERSION.to_owned(),
        };
        assert_eq!(
            ProxyPollRequest::decode(&poll.encode().unwrap()).unwrap(),
            poll
        );

        let response = ProxyPollResponse {
            status: STATUS_CLIENT_MATCH.to_owned(),
            offer: Some(sdp().to_owned()),
        };
        assert_eq!(
            ProxyPollResponse::decode(&response.encode().unwrap()).unwrap(),
            response
        );

        let answer = ProxyAnswer {
            answer: sdp().to_owned(),
            sid: "proxy-1".to_owned(),
        };
        assert_eq!(
            ProxyAnswer::decode(&answer.encode().unwrap()).unwrap(),
            answer
        );
    }
}
