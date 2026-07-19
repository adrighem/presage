/// Whether to trust or reject new identities
#[derive(Debug, Clone)]
pub enum OnNewIdentity {
    Reject,
    Trust,
    /// Trust replacements for receiving and for unverified contacts, while
    /// keeping verified-contact replacements pending for explicit approval.
    TrustUnverified,
}
