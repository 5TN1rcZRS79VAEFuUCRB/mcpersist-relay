use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "kind")]
#[serde(rename_all = "snake_case")]
pub enum ServerboundControlMessage {
    ProbeCapabilities,
    /// `key` is a world's secret: the same key always gets the same name. Stock e4mc
    /// clients send no key and get a random name.
    RequestDomainAssignment {
        #[serde(default)]
        key: Option<String>,
    },
    DialtoneRegisterTicket { ticket: String },
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "kind")]
#[serde(rename_all = "snake_case")]
pub enum ClientboundControlMessage {
    UnknownMessage,
    HasCapabilities { caps: Vec<String> },
    DomainAssignmentComplete { domain: String },
    DomainAssignmentFailed { reason: String },
    RequestMessageBroadcast { message: String },
    TicketRegistered,
}
