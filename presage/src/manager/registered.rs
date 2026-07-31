use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::TimeZone;
use futures::future::LocalBoxFuture;
use futures::stream::FuturesUnordered;
use futures::{future, AsyncReadExt, FutureExt, Stream, StreamExt};
use libsignal_service::libsignal_account_keys::AccountEntropyPool;
use libsignal_service::prelude::SessionStoreExt;
use libsignal_service::proto::addressable_message::Author;
use libsignal_service::protocol::{ProtocolAddress, SessionStore};
use libsignal_service::provisioning::ProvisioningSecrets;
use libsignal_service::{
    attachment_cipher::decrypt_in_place,
    cipher,
    configuration::{Endpoint, ServiceConfiguration, SignalServers},
    content::{Content, ContentBody, Metadata},
    encrypt_device_name,
    groups_v2::{
        decrypt_group, GroupChange, GroupDecodingError, GroupOperations, GroupsManager,
        InMemoryCredentialsCache,
    },
    messagepipe::{Incoming, MessagePipe, ServiceCredentials},
    prelude::{
        phonenumber::PhoneNumber, MasterKey, MessageSenderError, ProtobufMessage,
        StorageServiceKey, Uuid,
    },
    profile_cipher::ProfileCipher,
    proto::{
        data_message::Delete,
        group_change,
        manifest_record::identifier,
        storage_record,
        sync_message::{self, sticker_pack_operation, StickerPackOperation},
        AttachmentPointer, DataMessage, EditMessage, GroupChangeResponse, GroupContextV2,
        GroupResponse, NullMessage, StorageRecord, SyncMessage, Verified,
    },
    protocol::{
        Aci, DeviceId, IdentityKeyStore, SenderCertificate, ServiceId, ServiceIdKind, Username,
    },
    provisioning::ProvisioningError,
    push_service::{HttpAuthOverride, PushService, ServiceError, ServiceIds, DEFAULT_DEVICE_ID},
    receiver::MessageReceiver,
    sender::{AttachmentSpec, AttachmentUploadError},
    sticker_cipher::derive_key,
    unidentified_access::UnidentifiedAccess,
    utils::TryIntoE164,
    websocket::{
        self,
        account::{AccountAttributes, DeviceCapabilities, DeviceInfo, WhoAmIResponse},
        SignalWebSocket,
    },
    zkgroup::{
        groups::{GroupMasterKey, GroupSecretParams},
        profiles::ProfileKey,
        GroupMasterKeyBytes,
    },
    AccountManager, Profile, ServiceIdExt, StorageService,
};
use rand::rng;
use reqwest::{header::HeaderMap, header::CONTENT_TYPE, Method, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::sync::Mutex;
use tracing::{debug, error, info, trace, warn};
use url::Url;

use crate::model::contacts::Contact;
use crate::serde::serde_profile_key;
use crate::store::{
    ContentExt, ContentsStore, Sticker, StickerPack, StickerPackManifest, Store, Thread,
};
use crate::{model::groups::Group, AvatarBytes, Error, Manager};

pub use crate::model::messages::Received;

type ServiceCipher<S> = cipher::ServiceCipher<S>;
type MessageSender<S> = libsignal_service::prelude::MessageSender<S>;
const GROUP_LEAVE_REVISION_ATTEMPTS: usize = 3;
const GROUPS_V2_ENDPOINT: &str = "/v2/groups/";
const SIGNAL_TIMESTAMP_HEADER: &str = "x-signal-timestamp";
const ATTACHMENT_MIN_PADDED_PLAINTEXT_SIZE: u128 = 541;
const ATTACHMENT_PRIVACY_PADDING_DENOMINATOR: u128 = 20;
const ATTACHMENT_CIPHER_BLOCK_SIZE: u128 = 16;
const ATTACHMENT_IV_SIZE: u128 = 16;
const ATTACHMENT_MAC_SIZE: u128 = 32;
const ATTACHMENT_MIN_CIPHERTEXT_SIZE: usize = 64;
const CONTACT_PROFILE_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProfileUpdateObservation {
    sequence: u64,
    profile_key: [u8; 32],
}

#[derive(Clone)]
struct ContactProfileUpdate {
    sender: ServiceId,
    profile_key: ProfileKey,
    observation_timestamp: u64,
    expire_timer: u32,
    expire_timer_version: u32,
}

#[derive(Clone)]
struct QueuedContactProfileUpdate {
    update: ContactProfileUpdate,
    observation: ProfileUpdateObservation,
}

#[derive(Default)]
struct ContactUpdateCoordinatorState {
    locks: HashMap<Uuid, Arc<Mutex<()>>>,
    latest_profile_updates: HashMap<Uuid, ProfileUpdateObservation>,
    pending_profile_updates: HashMap<Uuid, QueuedContactProfileUpdate>,
    next_profile_update_sequence: u64,
}

#[derive(Clone, Default)]
struct ContactUpdateCoordinator {
    inner: Arc<Mutex<ContactUpdateCoordinatorState>>,
}

impl ContactUpdateCoordinator {
    async fn contact_lock(&self, uuid: Uuid) -> Arc<Mutex<()>> {
        let mut state = self.inner.lock().await;
        state.locks.entry(uuid).or_default().clone()
    }

    async fn enqueue_profile_update(&self, uuid: Uuid, update: ContactProfileUpdate) {
        let contact_lock = self.contact_lock(uuid).await;
        let _contact_guard = contact_lock.lock().await;
        let mut state = self.inner.lock().await;
        state.next_profile_update_sequence = state
            .next_profile_update_sequence
            .checked_add(1)
            .expect("contact profile update sequence was exhausted");
        let observation = ProfileUpdateObservation {
            sequence: state.next_profile_update_sequence,
            profile_key: update.profile_key.bytes,
        };
        state.latest_profile_updates.insert(uuid, observation);
        state.pending_profile_updates.insert(
            uuid,
            QueuedContactProfileUpdate {
                update,
                observation,
            },
        );
    }

    async fn take_profile_update(&self, uuid: Uuid) -> Option<QueuedContactProfileUpdate> {
        self.inner
            .lock()
            .await
            .pending_profile_updates
            .remove(&uuid)
    }

    async fn has_pending_profile_update(&self, uuid: Uuid) -> bool {
        self.inner
            .lock()
            .await
            .pending_profile_updates
            .contains_key(&uuid)
    }

    async fn coalesce_current_profile_update(
        &self,
        uuid: Uuid,
        queued: QueuedContactProfileUpdate,
    ) -> Option<QueuedContactProfileUpdate> {
        let mut state = self.inner.lock().await;
        let current = *state.latest_profile_updates.get(&uuid)?;
        if current.profile_key != queued.update.profile_key.bytes {
            return None;
        }
        if state
            .pending_profile_updates
            .get(&uuid)
            .is_some_and(|pending| pending.observation == current)
        {
            return state.pending_profile_updates.remove(&uuid);
        }
        (current == queued.observation).then_some(queued)
    }
}

#[derive(Default)]
struct ContactProfileWorkerQueue {
    workers: FuturesUnordered<LocalBoxFuture<'static, Uuid>>,
    active: HashSet<Uuid>,
}

impl ContactProfileWorkerQueue {
    fn is_empty(&self) -> bool {
        self.workers.is_empty()
    }

    fn start<S: Store>(
        &mut self,
        store: S,
        identified_websocket: SignalWebSocket<websocket::Identified>,
        contact_updates: ContactUpdateCoordinator,
        sender_uuid: Uuid,
    ) {
        if self.active.insert(sender_uuid) {
            self.workers.push(
                run_contact_profile_worker(
                    store,
                    identified_websocket,
                    contact_updates,
                    sender_uuid,
                )
                .map(move |_| sender_uuid)
                .boxed_local(),
            );
        }
    }

    fn complete(&mut self, sender_uuid: Uuid) {
        self.active.remove(&sender_uuid);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StorageGroupSnapshotError {
    DuplicateManifestKey,
    ResponseKeySetMismatch,
}

fn storage_group_item_keys(
    manifest: &libsignal_service::proto::ManifestRecord,
) -> Result<Vec<Vec<u8>>, StorageGroupSnapshotError> {
    let keys = manifest
        .identifiers
        .iter()
        .filter(|identifier| identifier.r#type == identifier::Type::Groupv2 as i32)
        .map(|identifier| identifier.raw.clone())
        .collect::<Vec<_>>();
    let unique = keys.iter().collect::<HashSet<_>>();
    if unique.len() != keys.len() {
        return Err(StorageGroupSnapshotError::DuplicateManifestKey);
    }
    Ok(keys)
}

fn match_storage_group_records(
    requested: &[Vec<u8>],
    returned: Vec<(Vec<u8>, StorageRecord)>,
) -> Result<Vec<StorageRecord>, StorageGroupSnapshotError> {
    let requested_keys = requested.iter().cloned().collect::<HashSet<_>>();
    if requested_keys.len() != requested.len() {
        return Err(StorageGroupSnapshotError::DuplicateManifestKey);
    }

    let mut records = HashMap::with_capacity(returned.len());
    for (key, record) in returned {
        if !requested_keys.contains(&key) || records.insert(key, record).is_some() {
            return Err(StorageGroupSnapshotError::ResponseKeySetMismatch);
        }
    }
    if records.len() != requested.len() {
        return Err(StorageGroupSnapshotError::ResponseKeySetMismatch);
    }

    requested
        .iter()
        .map(|key| {
            records
                .remove(key)
                .ok_or(StorageGroupSnapshotError::ResponseKeySetMismatch)
        })
        .collect()
}

fn group_has_member(group: &libsignal_service::groups_v2::Group, aci: Aci) -> bool {
    group.members.iter().any(|member| member.aci == aci)
}

fn stale_group_keys(
    stored: impl IntoIterator<Item = GroupMasterKeyBytes>,
    active: &HashSet<GroupMasterKeyBytes>,
) -> Vec<GroupMasterKeyBytes> {
    stored
        .into_iter()
        .filter(|key| !active.contains(key))
        .collect()
}

fn group_candidate_keys(
    manifest: impl IntoIterator<Item = GroupMasterKeyBytes>,
    cached: impl IntoIterator<Item = GroupMasterKeyBytes>,
) -> HashSet<GroupMasterKeyBytes> {
    manifest.into_iter().chain(cached).collect()
}

fn active_group_from_snapshot(
    master_key: GroupMasterKeyBytes,
    group: libsignal_service::groups_v2::Group,
    own_aci: Aci,
) -> Option<(GroupMasterKeyBytes, Group)> {
    group_has_member(&group, own_aci).then(|| (master_key, Group::from(group)))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GroupLeaveConfirmationError {
    StillMember,
}

fn confirmed_group_after_leave(
    group: Option<libsignal_service::groups_v2::Group>,
    own_aci: Aci,
) -> Result<Option<Group>, GroupLeaveConfirmationError> {
    match group {
        Some(group) if group_has_member(&group, own_aci) => {
            Err(GroupLeaveConfirmationError::StillMember)
        }
        Some(group) => Ok(Some(Group::from(group))),
        None => Ok(None),
    }
}

fn build_leave_group_actions(
    operations: &GroupOperations,
    own_aci: Aci,
    version: u32,
) -> Result<group_change::Actions, GroupDecodingError> {
    let own_uuid: Uuid = own_aci.into();
    Ok(group_change::Actions {
        // Requests carry the raw ACI. The group service replaces this with the
        // encrypted service ID in the signed response.
        source_user_id: own_uuid.as_bytes().to_vec(),
        version,
        delete_members: vec![operations.build_remove_member_action(own_aci)?],
        ..Default::default()
    })
}

fn signal_response_timestamp(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(SIGNAL_TIMESTAMP_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthoritativeGroupResponse {
    Current,
    Inactive,
    Error,
}

fn classify_authoritative_group_response(
    status: StatusCode,
    headers: &HeaderMap,
) -> Result<AuthoritativeGroupResponse, ServiceError> {
    if signal_response_timestamp(headers).is_none() {
        return Err(ServiceError::InvalidFrame {
            reason: "groups v2 response had no valid timestamp",
        });
    }
    if matches!(status, StatusCode::FORBIDDEN | StatusCode::NOT_FOUND) {
        Ok(AuthoritativeGroupResponse::Inactive)
    } else if status.is_success() {
        Ok(AuthoritativeGroupResponse::Current)
    } else {
        Ok(AuthoritativeGroupResponse::Error)
    }
}

fn group_from_response(
    response: GroupResponse,
) -> Result<libsignal_service::proto::Group, ServiceError> {
    response.group.ok_or(ServiceError::GroupsV2Error)
}

async fn groups_v2_response_error(response: reqwest::Response) -> ServiceError {
    let status = response.status();
    if status == StatusCode::UNAUTHORIZED {
        return ServiceError::Unauthorized;
    }
    let body = response.text().await.unwrap_or_default();
    let body = body.chars().take(1024).collect();
    ServiceError::UnhandledResponseCode { status, body }
}

async fn fetch_authoritative_group(
    groups_manager: &mut GroupsManager<InMemoryCredentialsCache>,
    push_service: &PushService,
    master_key: &GroupMasterKeyBytes,
) -> Result<Option<libsignal_service::proto::Group>, ServiceError> {
    let secret_params = GroupSecretParams::derive_from_master_key(GroupMasterKey::new(*master_key));
    let authorization = groups_manager
        .get_authorization_for_today(&mut rand::rng(), secret_params)
        .await?;
    let response = push_service
        .request(
            Method::GET,
            Endpoint::storage(GROUPS_V2_ENDPOINT),
            HttpAuthOverride::Identified(authorization),
        )?
        .send()
        .await
        .map_err(ServiceError::from)?;

    match classify_authoritative_group_response(response.status(), response.headers())? {
        AuthoritativeGroupResponse::Inactive => return Ok(None),
        AuthoritativeGroupResponse::Error => {
            return Err(groups_v2_response_error(response).await);
        }
        AuthoritativeGroupResponse::Current => {}
    }

    let response = GroupResponse::decode(response.bytes().await?)?;
    group_from_response(response).map(Some)
}

fn is_expected_leave_change(
    change: &libsignal_service::groups_v2::GroupChanges,
    expected_group_id: [u8; 32],
    own_aci: Aci,
    version: u32,
) -> bool {
    change.group_id == expected_group_id
        && change.editor == own_aci
        && change.version == version
        && change
            .changes
            .iter()
            .any(|item| matches!(item, GroupChange::DeleteMember(aci) if *aci == own_aci))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistrationType {
    Primary,
    Secondary,
}

/// Result details for a group leave accepted by the Signal group service.
///
/// Any returned value means membership was irreversibly removed on the server.
/// The flags expose best-effort cleanup which callers may report as a nonfatal
/// warning without restoring a group the account has already left. A peer
/// notification is considered sent when no new leave change was required.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct LeaveGroupOutcome {
    pub peer_notification_sent: bool,
    pub local_group_removed: bool,
}

/// Manager state when the client is registered and can send and receive messages from Signal
pub struct Registered {
    pub(crate) identified_push_service: OnceLock<PushService>,
    pub(crate) unidentified_push_service: OnceLock<PushService>,
    pub(crate) identified_websocket: Arc<Mutex<Option<SignalWebSocket<websocket::Identified>>>>,
    pub(crate) unidentified_websocket: Arc<Mutex<Option<SignalWebSocket<websocket::Unidentified>>>>,
    pub(crate) unidentified_sender_certificate: Arc<Mutex<Option<SenderCertificate>>>,
    contact_updates: ContactUpdateCoordinator,

    pub(crate) data: RegistrationData,
}

impl fmt::Debug for Registered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registered").finish_non_exhaustive()
    }
}

impl Registered {
    pub(crate) fn with_data(data: RegistrationData) -> Self {
        Self {
            identified_push_service: Default::default(),
            unidentified_push_service: Default::default(),
            identified_websocket: Default::default(),
            unidentified_websocket: Default::default(),
            unidentified_sender_certificate: Default::default(),
            contact_updates: Default::default(),
            data,
        }
    }

    fn servers(&self) -> SignalServers {
        self.data.signal_servers
    }

    fn service_configuration(&self) -> ServiceConfiguration {
        self.servers().into()
    }

    pub fn device_id(&self) -> DeviceId {
        self.data
            .device_id
            .and_then(|d| d.try_into().ok())
            .unwrap_or(*DEFAULT_DEVICE_ID)
    }

    pub(crate) fn identified_push_service(&self) -> PushService {
        self.identified_push_service
            .get_or_init(|| {
                PushService::new(self.servers(), Some(self.credentials()), crate::USER_AGENT)
            })
            .clone()
    }

    pub(crate) fn credentials(&self) -> ServiceCredentials {
        ServiceCredentials {
            aci: Some(self.data.service_ids.aci),
            pni: Some(self.data.service_ids.pni),
            phonenumber: (&self.data.phone_number)
                .try_into_e164()
                .expect("valid phone number"),
            password: Some(self.data.password.clone()),
            device_id: self.data.device_id.and_then(|d| d.try_into().ok()),
        }
    }
}

/// Registration data like device name, and credentials to connect to Signal
#[derive(Serialize, Deserialize, Clone)]
pub struct RegistrationData {
    pub signal_servers: SignalServers,
    pub device_name: Option<String>,
    pub phone_number: PhoneNumber,
    #[serde(flatten)]
    pub service_ids: ServiceIds,
    pub(crate) password: String,
    pub device_id: Option<u32>,
    pub registration_id: u32,
    #[serde(default)]
    pub pni_registration_id: Option<u32>,
    #[serde(with = "serde_profile_key")]
    pub(crate) profile_key: ProfileKey,
}

impl RegistrationData {
    /// Our own profile key
    pub fn profile_key(&self) -> ProfileKey {
        self.profile_key
    }

    /// The name of the device (if linked as secondary)
    pub fn device_name(&self) -> Option<&str> {
        self.device_name.as_deref()
    }
}

impl<S: Store> Manager<S, Registered> {
    /// Loads a previously registered account from the implemented [Store].
    ///
    /// Returns a instance of [Manager] you can use to send & receive messages.
    pub async fn load_registered(store: S) -> Result<Self, Error<S::Error>> {
        let registration_data = store
            .load_registration_data()
            .await?
            .ok_or(Error::NotYetRegisteredError)?;

        let registered = Registered::with_data(registration_data);

        if let Some(sender_certificate) = store.sender_certificate().await? {
            registered
                .unidentified_sender_certificate
                .lock()
                .await
                .replace(sender_certificate);
        }

        Ok(Self {
            store,
            state: Arc::new(registered),
        })
    }

    /// Returns a handle to the [Store] implementation.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Returns a handle on the [RegistrationData].
    pub fn registration_data(&self) -> &RegistrationData {
        &self.state.data
    }

    /// Returns a clone of a cached push service (with credentials).
    ///
    /// If no service is yet cached, it will create and cache one.
    fn identified_push_service(&self) -> PushService {
        self.state.identified_push_service()
    }

    /// Returns a clone of a cached push service (without credentials).
    ///
    /// If no service is yet cached, it will create and cache one.
    fn unidentified_push_service(&self) -> PushService {
        self.state
            .unidentified_push_service
            .get_or_init(|| PushService::new(self.state.servers(), None, crate::USER_AGENT))
            .clone()
    }

    /// Returns the current identified websocket, or creates a new one
    ///
    /// A new one is created if the current websocket is closed, or if there is none yet.
    async fn identified_websocket(
        &self,
        require_unused: bool,
    ) -> Result<SignalWebSocket<websocket::Identified>, Error<S::Error>> {
        let mut identified_ws = self.state.identified_websocket.lock().await;
        match identified_ws
            .as_ref()
            .filter(|ws| !ws.is_closed())
            .filter(|ws| !(require_unused && ws.is_used()))
        {
            Some(ws) => Ok(ws.clone()),
            None => {
                let headers = &[("X-Signal-Receive-Stories", "false")];
                let ws = self
                    .identified_push_service()
                    .ws(
                        "/v1/websocket/",
                        "/v1/keepalive",
                        headers,
                        Some(self.credentials()),
                    )
                    .await?;
                identified_ws.replace(ws.clone());
                debug!("initialized identified websocket");

                Ok(ws)
            }
        }
    }

    /// Returns the current unidentified websocket, or creates a new one
    ///
    /// A new one is created if the current websocket is closed, or if there is none yet.
    async fn unidentified_websocket(
        &self,
    ) -> Result<SignalWebSocket<websocket::Unidentified>, Error<S::Error>> {
        let mut unidentified_ws = self.state.unidentified_websocket.lock().await;
        match unidentified_ws.as_ref().filter(|ws| !ws.is_closed()) {
            Some(ws) => Ok(ws.clone()),
            None => {
                let ws = self
                    .unidentified_push_service()
                    .ws("/v1/websocket/", "/v1/keepalive", &[], None)
                    .await?;
                unidentified_ws.replace(ws.clone());
                debug!("initialized unidentified websocket");

                Ok(ws)
            }
        }
    }

    /// Request the primary device to encrypt & send all of its contacts.
    ///
    /// **Note**: If successful, the contacts are not yet received and stored, but will only be
    /// processed when they're received after polling on the
    pub async fn request_contacts(&mut self) -> Result<(), Error<S::Error>> {
        trace!("requesting contacts sync");
        let sync_message = SyncMessage {
            request: Some(sync_message::Request {
                r#type: Some(sync_message::request::Type::Contacts.into()),
            }),
            ..SyncMessage::with_padding(&mut rand::rng())
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;

        self.send_message(self.state.data.service_ids.aci(), sync_message, timestamp)
            .await?;

        Ok(())
    }

    async fn sender_certificate(&self) -> Result<SenderCertificate, Error<S::Error>> {
        let needs_renewal = |sender_certificate: Option<&SenderCertificate>| -> bool {
            if sender_certificate.is_none() {
                return true;
            }

            let seconds_since_epoch = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();

            if let Some(expiration) = sender_certificate.and_then(|s| s.expiration().ok()) {
                expiration.epoch_millis() / 1000 <= seconds_since_epoch + 600
            } else {
                true
            }
        };

        let mut unidentified_sender_certificate =
            self.state.unidentified_sender_certificate.lock().await;
        if needs_renewal(unidentified_sender_certificate.as_ref()) {
            let sender_certificate = self
                .identified_websocket(false)
                .await?
                .get_uuid_only_sender_certificate()
                .await?;
            self.store
                .save_sender_certificate(&sender_certificate)
                .await?;
            unidentified_sender_certificate.replace(sender_certificate);
        }

        Ok(unidentified_sender_certificate
            .clone()
            .expect("logic error"))
    }

    async fn master_key(&self) -> Result<Option<MasterKey>, Error<S::Error>> {
        let from_store = self.store().fetch_master_key().await?;

        if let Some(key) = from_store {
            Ok(Some(key))
        } else {
            let aep = self.account_entropy_pool().await?;
            Ok(aep.map(|aep| {
                MasterKey::from_slice(aep.derive_svr_key().as_slice())
                    .expect("Derived SVR key from account entropy pool to be a valid master key")
            }))
        }
    }

    async fn account_entropy_pool(&self) -> Result<Option<AccountEntropyPool>, Error<S::Error>> {
        let from_store = self.store().fetch_account_entropy_pool().await?;

        if let Some(key) = from_store {
            Ok(Some(key))
        } else if self.registration_type() == RegistrationType::Primary {
            let key = AccountEntropyPool::generate(&mut rand::rng());
            self.store().store_account_entropy_pool(Some(&key)).await?;
            Ok(Some(key))
        } else {
            Ok(None)
        }
    }

    pub async fn submit_recaptcha_challenge(
        &self,
        token: &str,
        captcha: &str,
    ) -> Result<(), Error<S::Error>> {
        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            self.identified_websocket(false).await?,
            None,
        );
        account_manager
            .submit_recaptcha_challenge(token, captcha)
            .await?;
        Ok(())
    }

    /// Fetches basic information on the registered device.
    pub async fn whoami(&self) -> Result<WhoAmIResponse, Error<S::Error>> {
        Ok(self.identified_websocket(false).await?.whoami().await?)
    }

    pub fn device_id(&self) -> DeviceId {
        self.state.device_id()
    }

    /// Fetches the profile (name, about, status emoji) of the registered user.
    pub async fn retrieve_profile(&mut self) -> Result<Profile, Error<S::Error>> {
        self.retrieve_profile_by_uuid(self.state.data.service_ids.aci, self.state.data.profile_key)
            .await
    }

    /// Fetches the profile of the provided user by UUID and profile key.
    pub async fn retrieve_profile_by_uuid(
        &mut self,
        aci: impl Into<Aci>,
        profile_key: ProfileKey,
    ) -> Result<Profile, Error<S::Error>> {
        let aci = aci.into();

        // Check if profile is cached.
        // TODO: Create a migration in the store removing all profiles.
        // TODO: Is there some way to know if this is outdated?
        if let Some(profile) = self
            .store
            .profile(aci.into(), profile_key)
            .await
            .ok()
            .flatten()
        {
            return Ok(profile);
        }

        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            self.identified_websocket(false).await?,
            Some(profile_key),
        );

        let profile = account_manager.retrieve_profile(aci).await?;

        let _ = self
            .store
            .save_profile(aci.into(), profile_key, profile.clone())
            .await;
        Ok(profile)
    }

    /// Updates the user's profile information.
    pub async fn update_profile(
        &mut self,
        name: libsignal_service::profile_name::ProfileName<String>,
        about: Option<String>,
        emoji: Option<String>,
    ) -> Result<(), Error<S::Error>> {
        let aci = self.state.data.service_ids.aci();
        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            self.identified_websocket(false).await?,
            Some(self.state.data.profile_key),
        );

        account_manager
            .upload_versioned_profile_without_avatar::<_, String>(
                aci,
                name,
                about,
                emoji,
                true, // retain_avatar
                &mut rand::rng(),
            )
            .await?;

        // Retrieve and save locally so we have the updated version
        let profile = account_manager.retrieve_profile(aci).await?;
        let _ = self
            .store
            .save_profile(aci.into(), self.state.data.profile_key, profile)
            .await;

        Ok(())
    }

    pub async fn retrieve_group_avatar(
        &mut self,
        context: GroupContextV2,
    ) -> Result<Option<AvatarBytes>, Error<S::Error>> {
        let master_key_bytes = context
            .master_key()
            .try_into()
            .expect("Master key bytes to be of size 32.");

        // Check if group avatar is cached.
        // TODO: Is there some way to know if this is outdated?
        if let Some(avatar) = self
            .store
            .group_avatar(master_key_bytes)
            .await
            .ok()
            .flatten()
        {
            return Ok(Some(avatar));
        }

        let mut gm = Box::pin(self.groups_manager()).await?;
        let Some(group) = upsert_group(
            &self.store,
            &mut gm,
            context.master_key(),
            &context.revision(),
        )
        .await?
        else {
            return Ok(None);
        };

        // Empty path means no avatar was set.
        if group.avatar.is_empty() {
            return Ok(None);
        }

        let avatar = gm
            .retrieve_avatar(
                &group.avatar,
                GroupSecretParams::derive_from_master_key(GroupMasterKey::new(master_key_bytes)),
            )
            .await?;
        if let Some(avatar) = &avatar {
            let _ = self.store.save_group_avatar(master_key_bytes, avatar).await;
        }
        Ok(avatar)
    }

    pub async fn retrieve_profile_avatar_by_uuid(
        &mut self,
        uuid: Uuid,
        profile_key: ProfileKey,
    ) -> Result<Option<AvatarBytes>, Error<S::Error>> {
        // Check if profile avatar is cached.
        // TODO: Is there some way to know if this is outdated?
        if let Some(avatar) = self
            .store
            .profile_avatar(uuid, profile_key)
            .await
            .ok()
            .flatten()
        {
            return Ok(Some(avatar));
        }

        let profile =
            if let Some(profile) = self.store.profile(uuid, profile_key).await.ok().flatten() {
                profile
            } else {
                self.retrieve_profile_by_uuid(uuid, profile_key).await?
            };

        let Some(avatar) = profile.avatar.as_ref() else {
            return Ok(None);
        };

        let mut websocket = self.unidentified_websocket().await?;

        let mut avatar_stream = websocket.retrieve_profile_avatar(avatar).await?;
        // 10MB is what Signal Android allocates
        let mut contents = Vec::with_capacity(10 * 1024 * 1024);
        let len = avatar_stream.read_to_end(&mut contents).await?;
        contents.truncate(len);

        let cipher = ProfileCipher::new(profile_key);

        let avatar = cipher.decrypt_avatar(&contents)?;
        let _ = self
            .store
            .save_profile_avatar(uuid, profile_key, &avatar)
            .await;
        Ok(Some(avatar))
    }

    async fn groups_manager(
        &self,
    ) -> Result<GroupsManager<InMemoryCredentialsCache>, Error<S::Error>> {
        let service_configuration = self.state.service_configuration();
        let server_public_params = service_configuration.zkgroup_server_public_params;

        let groups_credentials_cache = InMemoryCredentialsCache::default();
        let groups_manager = GroupsManager::new(
            self.state.data.service_ids.clone(),
            self.identified_push_service(),
            self.unidentified_websocket().await?,
            groups_credentials_cache,
            server_public_params,
        );

        Ok(groups_manager)
    }

    /// Fetches the account's current group records from Signal Storage Service
    /// and refreshes their encrypted group metadata in the local store.
    ///
    /// Linked devices do not receive an authoritative legacy group snapshot.
    /// Storage Service is therefore required to discover existing groups that
    /// have not produced a message since this device was linked.
    pub async fn synchronize_storage_groups(&mut self) -> Result<usize, Error<S::Error>> {
        let master_key = self
            .master_key()
            .await?
            .ok_or(Error::MissingKeyError("master key".into()))?;
        let storage_key = StorageServiceKey::from_master_key(&master_key);
        let storage = StorageService::new(self.identified_push_service(), storage_key).await?;
        let manifest = storage.manifest().await?;
        let group_item_keys =
            storage_group_item_keys(&manifest).map_err(|_| Error::InvalidStorageGroupRecord)?;
        let record_ikm =
            (!manifest.record_ikm.is_empty()).then_some(manifest.record_ikm.as_slice());
        let returned = storage
            .read_items_with_keys(group_item_keys.clone(), record_ikm)
            .await?;
        let records = match_storage_group_records(&group_item_keys, returned)
            .map_err(|_| Error::IncompleteStorageGroupSnapshot)?;

        let mut manifest_group_keys = HashSet::new();

        for record in records {
            let Some(storage_record::Record::GroupV2(group_record)) = record.record else {
                return Err(Error::InvalidStorageGroupRecord);
            };
            let master_key: GroupMasterKeyBytes = group_record
                .master_key
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidStorageGroupRecord)?;
            if !manifest_group_keys.insert(master_key) {
                return Err(Error::InvalidStorageGroupRecord);
            }
        }

        let stored_keys = self
            .store()
            .groups()
            .await?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|(key, _)| key)
            .collect::<Vec<_>>();
        let candidates = group_candidate_keys(
            manifest_group_keys.iter().copied(),
            stored_keys.iter().copied(),
        );

        let mut groups_manager = self.groups_manager().await?;
        let push_service = self.identified_push_service();
        let own_aci = self.registration_data().service_ids.aci();
        let mut active_groups = Vec::new();

        for master_key in candidates {
            // Storage records do not carry a group revision. Always fetch the
            // current group state for manifest and cached candidates so a
            // manifest/group update race cannot drop an active group.
            let Some(encrypted) =
                fetch_authoritative_group(&mut groups_manager, &push_service, &master_key).await?
            else {
                // A timestamp-bearing GroupsV2 403 or 404 definitively means
                // this group is inactive. Other failures abort the refresh.
                continue;
            };
            let group = decrypt_group(&master_key, encrypted)?;
            if let Some(active_group) = active_group_from_snapshot(master_key, group, own_aci) {
                active_groups.push(active_group);
            }
        }

        // All network reads and decryptions above must succeed before the first
        // store mutation. A partial remote snapshot therefore never prunes a
        // previously valid local group.
        let active_keys = active_groups
            .iter()
            .map(|(key, _)| *key)
            .collect::<HashSet<_>>();
        let synchronized = active_keys.len();
        let stale_keys = stale_group_keys(stored_keys, &active_keys);
        self.store()
            .reconcile_groups(active_groups, stale_keys)
            .await?;

        Ok(synchronized)
    }

    /// Leave a GroupsV2 group and notify its remaining members.
    ///
    /// The current group state is fetched immediately before the authenticated
    /// mutation. Revision conflicts are refreshed and retried. A valid signed
    /// change proves success directly. If that proof is unavailable, a second
    /// authoritative read must confirm nonmembership before local state is
    /// changed. Notification and local cleanup failures after confirmed success
    /// are reflected in [`LeaveGroupOutcome`] because they cannot roll back the
    /// server-side membership change.
    pub async fn leave_group(
        &mut self,
        master_key: &GroupMasterKeyBytes,
    ) -> Result<LeaveGroupOutcome, Error<S::Error>> {
        let own_aci = self.registration_data().service_ids.aci();
        let secret_params =
            GroupSecretParams::derive_from_master_key(GroupMasterKey::new(*master_key));
        let expected_group_id = secret_params.get_group_identifier();
        let operations = GroupOperations::new(secret_params);
        let mut groups_manager = self.groups_manager().await?;
        let push_service = self.identified_push_service();

        for attempt in 0..GROUP_LEAVE_REVISION_ATTEMPTS {
            let Some(encrypted) =
                fetch_authoritative_group(&mut groups_manager, &push_service, master_key).await?
            else {
                return Ok(self.finish_already_left_group(master_key).await);
            };
            let current_group = decrypt_group(master_key, encrypted)?;
            if !group_has_member(&current_group, own_aci) {
                return Ok(self.finish_already_left_group(master_key).await);
            }

            let next_revision = current_group
                .version
                .checked_add(1)
                .ok_or(Error::InvalidGroupLeaveChange)?;
            let actions = build_leave_group_actions(&operations, own_aci, next_revision)
                .map_err(ServiceError::from)?;
            let authorization = groups_manager
                .get_authorization_for_today(&mut rand::rng(), secret_params)
                .await?;
            let response = push_service
                .request(
                    Method::PATCH,
                    Endpoint::storage(GROUPS_V2_ENDPOINT),
                    HttpAuthOverride::Identified(authorization),
                )?
                .header(CONTENT_TYPE, "application/x-protobuf")
                .body(actions.encode_to_vec())
                .send()
                .await
                .map_err(ServiceError::from)?;

            if response.status() == StatusCode::CONFLICT {
                if attempt + 1 < GROUP_LEAVE_REVISION_ATTEMPTS {
                    continue;
                }
                return Err(Error::GroupRevisionConflict);
            }
            if !response.status().is_success() {
                return Err(groups_v2_response_error(response).await.into());
            }
            let notification_timestamp =
                signal_response_timestamp(response.headers()).unwrap_or_else(|| {
                    warn!("Signal group leave response had no valid X-Signal-Timestamp; using local time");
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64
                });

            let mut updated_group = Group::from(current_group);
            updated_group.members.retain(|member| member.aci != own_aci);
            updated_group.revision = next_revision;

            let signed_change = match response.bytes().await {
                Ok(bytes) => {
                    let validation = (|| -> Result<_, ServiceError> {
                        let response = GroupChangeResponse::decode(bytes)?;
                        let signed = response.group_change.ok_or(ServiceError::GroupsV2Error)?;
                        let signature = signed
                            .server_signature
                            .as_slice()
                            .try_into()
                            .map_err(|_| ServiceError::GroupsV2Error)?;
                        self.state
                            .service_configuration()
                            .zkgroup_server_public_params
                            .verify_signature(&signed.actions, signature)
                            .map_err(ServiceError::from)?;
                        let decoded = operations
                            .decrypt_group_change(signed.clone())
                            .map_err(ServiceError::from)?;
                        if !is_expected_leave_change(
                            &decoded,
                            expected_group_id,
                            own_aci,
                            next_revision,
                        ) {
                            return Err(ServiceError::GroupsV2Error);
                        }
                        Ok(signed)
                    })();
                    match validation {
                        Ok(change) => Some(change),
                        Err(error) => {
                            warn!(%error, "Signal accepted the group leave but returned an invalid signed change");
                            None
                        }
                    }
                }
                Err(error) => {
                    warn!(%error, "Signal accepted the group leave but its signed change could not be read");
                    None
                }
            };

            if signed_change.is_none() {
                let authoritative_group =
                    fetch_authoritative_group(&mut groups_manager, &push_service, master_key)
                        .await?
                        .map(|encrypted| decrypt_group(master_key, encrypted))
                        .transpose()?;
                if let Some(confirmed_group) =
                    confirmed_group_after_leave(authoritative_group, own_aci)
                        .map_err(|_| Error::InvalidGroupLeaveChange)?
                {
                    updated_group = confirmed_group;
                }
            }

            return Ok(self
                .finish_accepted_group_leave(
                    master_key,
                    updated_group,
                    next_revision,
                    notification_timestamp,
                    signed_change,
                )
                .await);
        }

        Err(Error::GroupRevisionConflict)
    }

    async fn finish_already_left_group(
        &self,
        master_key: &GroupMasterKeyBytes,
    ) -> LeaveGroupOutcome {
        let local_group_removed = match self.store().remove_group(*master_key).await {
            Ok(()) => true,
            Err(error) => {
                warn!(%error, "Signal group was already left but cached state could not be removed");
                false
            }
        };
        LeaveGroupOutcome {
            peer_notification_sent: true,
            local_group_removed,
        }
    }

    async fn finish_accepted_group_leave(
        &mut self,
        master_key: &GroupMasterKeyBytes,
        updated_group: Group,
        revision: u32,
        timestamp: u64,
        signed_change: Option<libsignal_service::proto::GroupChange>,
    ) -> LeaveGroupOutcome {
        let prepared = match self.store().save_group(*master_key, updated_group).await {
            Ok(()) => true,
            Err(error) => {
                warn!(%error, "Signal group leave succeeded but updated state could not be saved");
                false
            }
        };
        let peer_notification_sent = if prepared {
            if let Some(signed_change) = signed_change {
                let message = DataMessage {
                    timestamp: Some(timestamp),
                    group_v2: Some(GroupContextV2 {
                        master_key: Some(master_key.to_vec()),
                        revision: Some(revision),
                        group_change: Some(signed_change.encode_to_vec()),
                    }),
                    ..Default::default()
                };
                match self
                    .send_message_to_group(master_key, message, timestamp)
                    .await
                {
                    Ok(()) => true,
                    Err(error) => {
                        warn!(%error, "Signal group leave succeeded but remaining members could not be notified");
                        false
                    }
                }
            } else {
                false
            }
        } else {
            false
        };

        let local_group_removed = match self.store().remove_group(*master_key).await {
            Ok(()) => true,
            Err(error) => {
                warn!(%error, "Signal group leave succeeded but cached state could not be removed");
                false
            }
        };

        LeaveGroupOutcome {
            peer_notification_sent,
            local_group_removed,
        }
    }

    /// Starts receiving and storing messages.
    ///
    /// As a client, it is heavily recommended to process incoming messages and wait for the `Received::QueueEmpty` messages
    /// until giving the ability for users to send messages. That way, all possible updates (sessions, profile keys, sender keys)
    /// are processed _before_ trying to encrypt and send messages, which might get rejected by recipients otherwise.
    ///
    /// Returns a [futures::Stream] of messages to consume. Messages will also be stored by the implementation of the [Store].
    pub async fn receive_messages(
        &mut self,
    ) -> Result<impl Stream<Item = Received>, Error<S::Error>> {
        struct StreamState<Receiver, Store, AciStore, PniStore> {
            store: Store,
            contact_updates: ContactUpdateCoordinator,
            profile_workers: ContactProfileWorkerQueue,
            queue_empty_pending: bool,
            identified_websocket: SignalWebSocket<websocket::Identified>,
            unidentified_websocket: SignalWebSocket<websocket::Unidentified>,
            encrypted_messages: Receiver,
            message_receiver: MessageReceiver,
            service_cipher_aci: ServiceCipher<AciStore>,
            service_cipher_pni: ServiceCipher<PniStore>,
            groups_manager: GroupsManager<InMemoryCredentialsCache>,
            service_ids: ServiceIds,
            message_sender: MessageSender<AciStore>,
            master_key: Option<MasterKey>,
            account_entropy_pool: Option<AccountEntropyPool>,
            registration_type: RegistrationType,
        }

        let identified_push_service = self.identified_push_service();
        // NB: here, we initialise a *fresh* Signal websocket, which means any other use of the previous one will go into nirvana
        let identified_websocket = self.identified_websocket(true).await?;

        let mut account_manager = AccountManager::new(
            identified_push_service.clone(),
            identified_websocket.clone(),
            None,
        );

        let store_inner = self.store.clone();
        let registration_data_inner = self.registration_data().clone();

        // We make a task to update the account attributes and refresh pre keys as needed that will
        // only yield a value if one of the two operations fail (stop signal).
        //
        // This is necessary because in this context, we can't do the classic tokio::spawn with a
        // oneshot::channel() or CancellationToken because of !Send constraints in the Store.
        let refresh_registration_task = async move {
            if let Err(error) =
                set_account_attributes(&mut account_manager, &store_inner, &registration_data_inner)
                    .await
            {
                error!(%error, "failed to set account attributes, this is problematic and should never happen!");
            }

            if let Err(error) = register_pre_keys(&store_inner, &mut account_manager).await {
                error!(%error, "failed to register pre-keys, this is problematic and should never happen!");
            }

            // Never return, which keeps the messages stream alive.
            future::pending::<()>().await
        };

        let encrypted_messages = MessagePipe::from_socket(identified_websocket.clone());

        let init = StreamState {
            store: self.store.clone(),
            contact_updates: self.state.contact_updates.clone(),
            profile_workers: ContactProfileWorkerQueue::default(),
            queue_empty_pending: false,
            identified_websocket,
            unidentified_websocket: self.unidentified_websocket().await?,
            encrypted_messages: Box::pin(encrypted_messages.stream()),
            message_receiver: MessageReceiver::new(identified_push_service),
            service_cipher_aci: self.new_service_cipher_aci(),
            service_cipher_pni: self.new_service_cipher_pni(),
            groups_manager: Box::pin(self.groups_manager()).await?,
            service_ids: self.state.data.service_ids.clone(),
            message_sender: self.new_message_sender().await?,
            master_key: self.master_key().await?,
            account_entropy_pool: self.account_entropy_pool().await?,
            registration_type: self.registration_type(),
        };

        debug!("starting to consume incoming message stream");

        let incoming_messages_stream = futures::stream::unfold(init, |mut state| {
            async move {
                loop {
                    if state.queue_empty_pending && state.profile_workers.is_empty() {
                        state.queue_empty_pending = false;
                        return Some((Received::QueueEmpty, state));
                    }

                    let incoming = if state.profile_workers.is_empty() {
                        state.encrypted_messages.next().await
                    } else {
                        tokio::select! {
                            biased;
                            completed = state.profile_workers.workers.next() => {
                                if let Some(sender_uuid) = completed {
                                    state.profile_workers.complete(sender_uuid);
                                    if state.contact_updates
                                        .has_pending_profile_update(sender_uuid)
                                        .await
                                    {
                                        state.profile_workers.start(
                                            state.store.clone(),
                                            state.identified_websocket.clone(),
                                            state.contact_updates.clone(),
                                            sender_uuid,
                                        );
                                    }
                                }
                                continue;
                            }
                            incoming = state.encrypted_messages.next() => incoming,
                        }
                    };
                    match incoming {
                        Some(Ok(Incoming::Envelope(envelope))) => {
                            let envelope = {
                                // the permit is released at the end of the block (impl Drop)
                                match ServiceId::parse_from_service_id_string(
                                    envelope.destination_service_id(),
                                ) {
                                    None | Some(ServiceId::Aci(_)) => {
                                        state
                                            .service_cipher_aci
                                            .open_envelope(envelope, &mut rng())
                                            .await
                                    }
                                    Some(ServiceId::Pni(pni)) => {
                                        if pni == state.service_ids.pni()
                                            && envelope.source_service_id.is_none()
                                        {
                                            warn!("Got a sealed sender message to our PNI? Invalid message, ignoring.");
                                            continue;
                                        }
                                        state
                                            .service_cipher_pni
                                            .open_envelope(envelope, &mut rng())
                                            .await
                                    }
                                }
                            };
                            match envelope {
                                Ok(Some(content)) => {
                                    if let ContentBody::DecryptionErrorMessage(e) = &content.body {
                                        error!(
                                            error = ?e,
                                            "got error decrypting a message"
                                        );
                                        continue;
                                    }

                                    if let ContentBody::SynchronizeMessage(SyncMessage {
                                        request: Some(request),
                                        ..
                                    }) = &content.body
                                    {
                                        use libsignal_service::content::sync_message::request::Type as RequestType;

                                        match request.r#type() {
                                            RequestType::Contacts => {
                                                let contacts = state
                                                    .store
                                                    .contacts()
                                                    .await
                                                    .map(|i| {
                                                        i.collect::<Result<Vec<_>, _>>()
                                                            .unwrap_or_default()
                                                    })
                                                    .unwrap_or_default();

                                                let mut message_sender =
                                                    state.message_sender.clone();
                                                let aci = state.service_ids.aci();
                                                tokio::task::spawn_local(async move {
                                                    let result = message_sender
                                                    .send_contact_details(
                                                        &ServiceId::Aci(aci),
                                                        None,
                                                        contacts.into_iter().map(|c| libsignal_service::sender::ContactDetails {
                                                            number: c.phone_number.map(|p| p.to_string()),
                                                            aci: Some(c.uuid.to_string()),
                                                            aci_binary: Some(c.uuid.into_bytes().into()),
                                                            name: Some(c.name),
                                                            avatar: c.avatar.map(|a| libsignal_service::proto::contact_details::Avatar {
                                                                content_type: Some(a.content_type),
                                                                length: a.reader.len().try_into().ok(),
                                                            }),
                                                            expire_timer: Some(c.expire_timer),
                                                            expire_timer_version: Some(c.expire_timer_version),
                                                            inbox_position: None,
                                                        }),
                                                        false,
                                                        true,
                                                    )
                                                    .await;

                                                    if let Err(error) = result {
                                                        warn!(%error, "Error sending contact details to other devices");
                                                    }
                                                });
                                            }
                                            RequestType::Keys => {
                                                let mut message_sender =
                                                    state.message_sender.clone();
                                                let account_entropy_pool = state
                                                    .account_entropy_pool
                                                    .as_ref()
                                                    .map(|aep| aep.to_string());
                                                let master = state
                                                    .master_key
                                                    .as_ref()
                                                    .map(|m| m.inner.to_vec());
                                                tokio::task::spawn_local(async move {
                                                    let result = message_sender.send_sync_message(SyncMessage {
                                                        keys: Some(libsignal_service::content::sync_message::Keys {
                                                            master,
                                                            account_entropy_pool,
                                                            media_root_backup_key: None,
                                                        }),
                                                        ..SyncMessage::with_padding(&mut rand::rng())
                                                    }).await;

                                                    if let Err(error) = result {
                                                        warn!(%error, "Error sending keys to other devices");
                                                    }
                                                });
                                            }
                                            RequestType::Blocked => {
                                                warn!("storing blocked user is not implemented yet! we will not report blocked users to the device requesting the sync.");
                                                let mut message_sender =
                                                    state.message_sender.clone();
                                                tokio::task::spawn_local(async move {
                                                    let result = message_sender.send_sync_message(SyncMessage {
                                                    blocked: Some(libsignal_service::content::sync_message::Blocked {
                                                        numbers: vec![],
                                                        acis: vec![],
                                                        acis_binary: vec![],
                                                        group_ids: vec![],
                                                    }),
                                                    ..SyncMessage::with_padding(&mut rand::rng())
                                                }).await;

                                                    if let Err(error) = result {
                                                        warn!(%error, "Error sending blocked contacts to other devices");
                                                    }
                                                });
                                            }
                                            t => {
                                                info!(type = ?t, "Got sync request of currently unhandled type")
                                            }
                                        }
                                    }

                                    // contacts synchronization sent from the primary device (happens after linking, or on demand)
                                    if let ContentBody::SynchronizeMessage(SyncMessage {
                                        contacts: Some(contacts),
                                        ..
                                    }) = &content.body
                                    {
                                        match state
                                            .message_receiver
                                            .retrieve_contacts(contacts)
                                            .await
                                        {
                                            Ok(contacts) => {
                                                info!("saving contacts");
                                                for contact in contacts.filter_map(Result::ok) {
                                                    if let Err(error) = save_synchronized_contact(
                                                        &mut state.store,
                                                        &state.contact_updates,
                                                        contact,
                                                    )
                                                    .await
                                                    {
                                                        warn!(%error, "failed to save contacts");
                                                        break;
                                                    }
                                                }
                                            }
                                            Err(error) => {
                                                warn!(%error, "failed to retrieve contacts");
                                            }
                                        }

                                        return Some((Received::Contacts, state));
                                    }

                                    // sticker pack operations
                                    if let ContentBody::SynchronizeMessage(SyncMessage {
                                        sticker_pack_operation,
                                        ..
                                    }) = &content.body
                                    {
                                        for operation in sticker_pack_operation {
                                            match operation.r#type() {
                                                sticker_pack_operation::Type::Install => {
                                                    let store = state.store.clone();
                                                    let unidentified_websocket =
                                                        state.unidentified_websocket.clone();
                                                    let operation = operation.clone();

                                                    // download stickers in the background
                                                    tokio::spawn(async move {
                                                        match download_sticker_pack(
                                                            store,
                                                            unidentified_websocket,
                                                            &operation,
                                                        )
                                                        .await
                                                        {
                                                            Ok(sticker_pack) => {
                                                                debug!(
                                                                "downloaded sticker pack: {} made by {}",
                                                                sticker_pack.manifest.title,
                                                                sticker_pack.manifest.author
                                                            );
                                                            }
                                                            Err(error) => error!(
                                                                %error,
                                                                "failed to download sticker pack"
                                                            ),
                                                        }
                                                    });
                                                }
                                                sticker_pack_operation::Type::Remove => match state
                                                    .store
                                                    .remove_sticker_pack(operation.pack_id())
                                                    .await
                                                {
                                                    Ok(was_present) => {
                                                        debug!(was_present, "removed stick pack")
                                                    }
                                                    Err(error) => {
                                                        error!(
                                                            %error,
                                                            "failed to remove sticker pack"
                                                        )
                                                    }
                                                },
                                            }
                                        }
                                    }

                                    // key synchronization sent from the primary device
                                    if let ContentBody::SynchronizeMessage(SyncMessage {
                                        keys: Some(keys),
                                        ..
                                    }) = &content.body
                                    {
                                        debug!("received key sync message");
                                        if state.registration_type == RegistrationType::Primary {
                                            warn!("received a key sync message as a primary device; ignoring")
                                        } else {
                                            match keys
                                                .account_entropy_pool
                                                .as_ref()
                                                .map(|s| AccountEntropyPool::from_str(s))
                                            {
                                                Some(Ok(aep)) => {
                                                    if let Err(error) = state
                                                        .store
                                                        .store_account_entropy_pool(Some(&aep))
                                                        .await
                                                    {
                                                        error!(%error, "failed to store account entropy pool");
                                                    }
                                                    state.account_entropy_pool = Some(aep);
                                                }
                                                Some(Err(error)) => {
                                                    warn!(%error, "cannot convert account entropy pool from string")
                                                }
                                                None => {}
                                            }
                                            match keys
                                                .master
                                                .as_ref()
                                                .map(|m| MasterKey::from_slice(m.as_slice()))
                                            {
                                                Some(Ok(master)) => {
                                                    if let Err(error) = state
                                                        .store
                                                        .store_master_key(Some(&master))
                                                        .await
                                                    {
                                                        error!(%error, "failed to store master key");
                                                    }
                                                    state.master_key = Some(master);
                                                }
                                                Some(Err(error)) => {
                                                    warn!(%error, "cannot convert master key from bytes; trying to populate from account entropy pool");
                                                    if let Some(aep) =
                                                        state.account_entropy_pool.as_ref()
                                                    {
                                                        state.master_key = Some(MasterKey::from_slice(aep.derive_svr_key().as_slice()).expect("svr key derived from account entropy pool to be a master key"));
                                                    }
                                                }
                                                None => {
                                                    trace!("master key not given in the sync message; trying to populate from account entropy pool");
                                                    if let Some(aep) =
                                                        state.account_entropy_pool.as_ref()
                                                    {
                                                        state.master_key = Some(MasterKey::from_slice(aep.derive_svr_key().as_slice()).expect("svr key derived from account entropy pool to be a master key"));
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    // group update
                                    if let ContentBody::DataMessage(DataMessage {
                                        group_v2:
                                            Some(GroupContextV2 {
                                                master_key: Some(master_key_bytes),
                                                revision: Some(revision),
                                                ..
                                            }),
                                        ..
                                    })
                                    | ContentBody::SynchronizeMessage(SyncMessage {
                                        sent:
                                            Some(sync_message::Sent {
                                                message:
                                                    Some(DataMessage {
                                                        group_v2:
                                                            Some(GroupContextV2 {
                                                                master_key: Some(master_key_bytes),
                                                                revision: Some(revision),
                                                                ..
                                                            }),
                                                        ..
                                                    }),
                                                ..
                                            }),
                                        ..
                                    }) = &content.body
                                    {
                                        // there's two things to implement: the group metadata (fetched from HTTP API)
                                        // and the group changes, which are part of the protobuf messages
                                        // this means we kinda need our own internal representation of groups inside of presage?
                                        if let Ok(Some(group)) = upsert_group(
                                            &state.store,
                                            &mut state.groups_manager,
                                            master_key_bytes,
                                            revision,
                                        )
                                        .await
                                        {
                                            trace!(?group, "upserted group");
                                        }
                                    }

                                    if let Err(error) = save_message(
                                        &mut state.store,
                                        &mut state.identified_websocket,
                                        &state.contact_updates,
                                        Some(&mut state.profile_workers),
                                        content.clone(),
                                        None,
                                    )
                                    .await
                                    {
                                        error!(%error, "error saving message to store");
                                    }

                                    return Some((Received::Content(Box::new(content)), state));
                                }
                                Ok(None) => {
                                    debug!("empty envelope, message will be skipped!")
                                }
                                Err(error) => {
                                    error!(%error, "error opening envelope, message will be skipped!");
                                }
                            }
                        }
                        Some(Ok(Incoming::QueueEmpty)) => {
                            debug!("got empty queue");
                            if !state.queue_empty_pending && state.account_entropy_pool.is_none() {
                                debug!("device does not have the needed keys; requesting from primary device");

                                let mut message_sender = state.message_sender.clone();
                                tokio::task::spawn_local(async move {
                                    let result = message_sender
                                        .send_sync_message(SyncMessage {
                                            request: Some(sync_message::Request {
                                                r#type: Some(
                                                    sync_message::request::Type::Keys.into(),
                                                ),
                                            }),
                                            ..SyncMessage::with_padding(&mut rand::rng())
                                        })
                                        .await;

                                    if let Err(error) = result {
                                        warn!(%error, "Error sending blocked contacts to other devices");
                                    }
                                });
                            }
                            if !state.profile_workers.is_empty() {
                                state.queue_empty_pending = true;
                                continue;
                            }
                            return Some((Received::QueueEmpty, state));
                        }
                        Some(Err(error)) => {
                            error!(%error, "unexpected error in message receiving loop")
                        }
                        None => return None,
                    }
                }
            }
        });

        Ok(Box::pin(
            // We use the returning of the async closure in take_until as a stop signal
            // if the future resolves *anything* the stream will end.
            incoming_messages_stream.take_until(refresh_registration_task),
        ))
    }

    /// Uses Signal's SGX contact discovery service to resolve a phone number to its matching account identity
    #[cfg(feature = "cdsi")]
    pub async fn discover_contacts_by_phone_number<P: TryIntoE164>(
        &mut self,
        phone_numbers: impl IntoIterator<Item = P>,
    ) -> Result<Vec<(PhoneNumber, Option<ServiceId>)>, Error<S::Error>> {
        use libsignal_service::websocket::directory::LookupRequest;

        let mut ws = self.identified_websocket(false).await?;

        let lookup_request = LookupRequest {
            new_e164s: phone_numbers
                .into_iter()
                .filter_map(|p| p.try_into_e164().ok())
                .collect(),
            ..Default::default()
        };

        Ok(ws
            .discover_contacts(lookup_request)
            .await?
            .into_iter()
            .map(|(e164, service_id)| {
                use libsignal_service::utils::phonenumber_from_signal;
                (phonenumber_from_signal(&e164), service_id)
            })
            .collect())
    }

    /// Resolves a username (which has a text part and an additional random number) to its account identity
    /// for sending messages.
    pub async fn lookup_username(
        &mut self,
        username: &str,
    ) -> Result<Option<Aci>, Error<S::Error>> {
        let username = Username::new(username)?;
        let mut ws = self.unidentified_websocket().await?;
        let resolved_username = ws.look_up_username(&username).await?;
        Ok(resolved_username)
    }

    /// Sends a messages to the provided [ServiceId].
    /// The timestamp should be set to now and is used by Signal mobile apps
    /// to order messages later, and apply reactions.
    ///
    /// This method will automatically update the [DataMessage::expire_timer] if it is set to
    /// [None] such that the chat will keep the current expire timer. If the expire timer is set,
    /// it will be used as is, and the expire timer version will be incremented.
    pub async fn send_message(
        &mut self,
        recipient: impl Into<ServiceId>,
        message: impl Into<ContentBody>,
        timestamp: u64,
    ) -> Result<(), Error<S::Error>> {
        let mut sender = self.new_message_sender().await?;
        let recipient = recipient.into();

        let online_only = false;
        // TODO: Populate this flag based on the recipient information
        //
        // Issue <https://github.com/whisperfish/presage/issues/252>
        let include_pni_signature = false;
        let thread = Thread::Contact(recipient);
        let mut content_body: ContentBody = message.into();

        self.restore_thread_timer(&thread, &mut content_body).await;

        let sender_certificate = self.sender_certificate().await?;
        let unidentified_access = self
            .store
            .profile_key(&recipient)
            .await?
            .map(|profile_key| UnidentifiedAccess {
                key: profile_key.derive_access_key().to_vec(),
                certificate: sender_certificate.clone(),
            });

        // we need to put our profile key in DataMessage
        if let ContentBody::DataMessage(message) = &mut content_body {
            message
                .profile_key
                .get_or_insert(self.state.data.profile_key().get_bytes().to_vec());
            message.required_protocol_version = Some(0);
        }

        ensure_data_message_timestamp(&mut content_body, timestamp);

        sender
            .send_message(
                &recipient,
                unidentified_access,
                content_body.clone(),
                timestamp,
                include_pni_signature,
                online_only,
            )
            .await?;

        // save the message
        let content = Content {
            metadata: Metadata {
                sender: self.state.data.service_ids.aci().into(),
                sender_device: self.state.device_id(),
                destination: recipient,
                server_guid: None,
                timestamp: chrono::Utc.timestamp_millis_opt(timestamp as i64).unwrap(),
                // Note: Currently no way to get the timestamp the server received the message; just use our timestamp as a fallback.
                server_timestamp: chrono::Utc.timestamp_millis_opt(timestamp as i64).unwrap(),
                needs_receipt: false,
                unidentified_sender: false,
                was_plaintext: false,
            },
            body: content_body,
        };

        let mut identified_websocket = self.identified_websocket(false).await?;
        save_message(
            &mut self.store,
            &mut identified_websocket,
            &self.state.contact_updates,
            None,
            content,
            Some(thread),
        )
        .await?;

        Ok(())
    }

    /// Uploads one attachment prior to linking them in a message.
    pub async fn upload_attachment(
        &self,
        spec: AttachmentSpec,
        contents: Vec<u8>,
    ) -> Result<Result<AttachmentPointer, AttachmentUploadError>, Error<S::Error>> {
        Ok(self
            .new_message_sender()
            .await?
            .upload_attachment(spec, contents, &mut rng())
            .await)
    }

    /// Uploads attachments prior to linking them in a message.
    pub async fn upload_attachments(
        &self,
        attachments: Vec<(AttachmentSpec, Vec<u8>)>,
    ) -> Result<Vec<Result<AttachmentPointer, AttachmentUploadError>>, Error<S::Error>> {
        if attachments.is_empty() {
            return Ok(Vec::new());
        }
        let sender = self.new_message_sender().await?;
        let upload = future::join_all(attachments.into_iter().map(move |(spec, contents)| {
            let mut sender = sender.clone();
            async move { sender.upload_attachment(spec, contents, &mut rng()).await }
        }));
        Ok(upload.await)
    }

    /// Sends one message in a group (v2). The `master_key_bytes` is required to have 32 elements.
    ///
    /// This method will automatically update the [DataMessage::expire_timer] if it is set to
    /// [None] such that the chat will keep the current expire timer.
    pub async fn send_message_to_group(
        &mut self,
        master_key_bytes: &[u8],
        message: impl Into<ContentBody>,
        timestamp: u64,
    ) -> Result<(), Error<S::Error>> {
        let mut content_body = message.into();
        let master_key_bytes = master_key_bytes
            .try_into()
            .expect("Master key bytes to be of size 32.");
        let thread = Thread::Group(master_key_bytes);

        self.restore_thread_timer(&thread, &mut content_body).await;
        ensure_data_message_timestamp(&mut content_body, timestamp);

        let mut sender = self.new_message_sender().await?;

        let mut groups_manager = Box::pin(self.groups_manager()).await?;
        let Some(group) =
            upsert_group(&self.store, &mut groups_manager, &master_key_bytes, &0).await?
        else {
            return Err(Error::UnknownGroup);
        };

        let sender_certificate = self.sender_certificate().await?;
        let mut recipients = Vec::new();
        for member in group
            .members
            .into_iter()
            .filter(|m| m.aci != self.state.data.service_ids.aci())
        {
            let unidentified_access =
                self.store
                    .profile_key(&member.aci.into())
                    .await?
                    .map(|profile_key| UnidentifiedAccess {
                        key: profile_key.derive_access_key().to_vec(),
                        certificate: sender_certificate.clone(),
                    });
            let include_pni_signature = false;
            recipients.push((
                member.aci.into(),
                unidentified_access,
                include_pni_signature,
            ));
        }

        let online_only = false;
        let results = sender
            .send_message_to_group(recipients, content_body.clone(), timestamp, online_only)
            .await;

        // TODO: Handle the NotFound error in the future by removing all sessions to this UUID and marking it as unregistered, not sending any messages to this contact anymore.
        results
            .into_iter()
            .find(|res| match res {
                Ok(_) => false,
                // Ignore any NotFound errors, those mean that e.g. some contact in a group deleted his account.
                Err(MessageSenderError::NotFound { service_id }) => {
                    debug!(service_id = %service_id.service_id_string(), "recipient not found, skipping sent message result");
                    false
                }
                // return first error if any
                Err(_) => true,
            })
            .transpose()?;

        let content = Content {
            metadata: Metadata {
                sender: self.state.data.service_ids.aci().into(),
                destination: self.state.data.service_ids.aci().into(),
                sender_device: self.state.device_id(),
                server_guid: None,
                timestamp: chrono::Utc.timestamp_millis_opt(timestamp as i64).unwrap(),
                // Note: Currently no way to get the timestamp the server received the message; just use our timestamp as a fallback.
                server_timestamp: chrono::Utc.timestamp_millis_opt(timestamp as i64).unwrap(),
                needs_receipt: false, // TODO: this is just wrong
                unidentified_sender: false,
                was_plaintext: false,
            },
            body: content_body,
        };

        let mut identified_websocket = self.identified_websocket(false).await?;
        save_message(
            &mut self.store,
            &mut identified_websocket,
            &self.state.contact_updates,
            None,
            content,
            Some(thread),
        )
        .await?;

        Ok(())
    }

    async fn restore_thread_timer(&mut self, thread: &Thread, content_body: &mut ContentBody) {
        let store_expire_timer = self.store.expire_timer(thread).await.unwrap_or_default();

        if let ContentBody::DataMessage(DataMessage {
            expire_timer: ref mut timer,
            expire_timer_version: ref mut version,
            ..
        }) = content_body
        {
            if timer.is_none() {
                *timer = store_expire_timer.and_then(|(t, _)| if t == 0 { None } else { Some(t) });
                *version = Some(store_expire_timer.map(|(_, v)| v).unwrap_or_default());
            } else {
                *version = Some(store_expire_timer.map(|(_, v)| v).unwrap_or_default() + 1);
            }
        }
    }

    /// Clears all sessions established with [recipient](ServiceId).
    pub async fn clear_sessions(&self, recipient: &ServiceId) -> Result<(), Error<S::Error>> {
        use libsignal_service::session_store::SessionStoreExt;
        self.store
            .aci_protocol_store()
            .delete_all_sessions(recipient)
            .await?;
        self.store
            .pni_protocol_store()
            .delete_all_sessions(recipient)
            .await?;
        Ok(())
    }

    /// Downloads and decrypts a single attachment.
    pub async fn get_attachment(
        &self,
        attachment_pointer: &AttachmentPointer,
    ) -> Result<Vec<u8>, Error<S::Error>> {
        self.get_attachment_inner(attachment_pointer, None).await
    }

    /// Downloads and decrypts a single attachment, rejecting it when its plaintext exceeds
    /// `max_size`.
    ///
    /// The download itself is bounded to include Signal's privacy padding and attachment
    /// encryption overhead. The encrypted stream is stopped as soon as it exceeds that bound.
    pub async fn get_attachment_with_size_limit(
        &self,
        attachment_pointer: &AttachmentPointer,
        max_size: usize,
    ) -> Result<Vec<u8>, Error<S::Error>> {
        self.get_attachment_inner(attachment_pointer, Some(max_size))
            .await
    }

    async fn get_attachment_inner(
        &self,
        attachment_pointer: &AttachmentPointer,
        max_size: Option<usize>,
    ) -> Result<Vec<u8>, Error<S::Error>> {
        let expected_digest = attachment_pointer
            .digest
            .as_ref()
            .ok_or_else(|| Error::UnexpectedAttachmentChecksum)?;

        let plaintext_len = attachment_pointer.size.and_then(|len| len.try_into().ok());
        if let (Some(max_size), Some(plaintext_len)) = (max_size, plaintext_len) {
            if plaintext_len > max_size {
                return Err(Error::AttachmentSizeLimitExceeded { max_size });
            }
        }

        let mut service = self.identified_push_service();
        let mut attachment_stream = service.get_attachment(attachment_pointer).await?;

        // We need the whole file for the crypto to check out
        let ciphertext_limit = max_size.map(attachment_ciphertext_size_limit);
        let Some(mut ciphertext) = read_attachment_ciphertext(
            &mut attachment_stream,
            plaintext_len.unwrap_or(0),
            ciphertext_limit,
        )
        .await?
        else {
            return Err(Error::AttachmentSizeLimitExceeded {
                max_size: max_size.expect("ciphertext limit requires plaintext limit"),
            });
        };
        let size_bytes = ciphertext.len();
        trace!(size_bytes, "downloaded encrypted attachment");

        let digest = sha2::Sha256::digest(&ciphertext);
        if &digest[..] != expected_digest {
            return Err(Error::UnexpectedAttachmentChecksum);
        }
        if !is_valid_attachment_ciphertext_size(ciphertext.len()) {
            return Err(Error::InvalidAttachmentCiphertext);
        }

        let key: [u8; 64] = attachment_pointer.key().try_into()?;

        // Offload decryption of large attachments to another thread.
        // Chose arbitrary threshold here.
        const DECRYPT_IN_THREAD_THRESHOLD: usize = 100 * 1024;
        if ciphertext.len() > DECRYPT_IN_THREAD_THRESHOLD {
            ciphertext = tokio::task::spawn_blocking(move || {
                decrypt_in_place(key, &mut ciphertext).map(|_| ciphertext)
            })
            .await
            .expect("decryption in another thread")?;
        } else {
            decrypt_in_place(key, &mut ciphertext)?;
        };

        if let Some(len) = plaintext_len {
            if len < ciphertext.len() {
                // remove padding
                ciphertext.truncate(len);
            }
        }

        if let Some(max_size) = max_size {
            if ciphertext.len() > max_size {
                return Err(Error::AttachmentSizeLimitExceeded { max_size });
            }
        }

        Ok(ciphertext)
    }

    /// Gets the metadata of a sticker
    pub async fn sticker_metadata(
        &mut self,
        pack_id: &[u8],
        sticker_id: u32,
    ) -> Result<Option<Sticker>, Error<S::Error>> {
        Ok(self.store.sticker_pack(pack_id).await?.and_then(|pack| {
            pack.manifest
                .stickers
                .iter()
                .find(|&x| x.id == sticker_id)
                .cloned()
        }))
    }

    /// Installs a sticker pack and notifies other registered devices
    pub async fn install_sticker_pack(
        &mut self,
        pack_id: &[u8],
        pack_key: &[u8],
    ) -> Result<(), Error<S::Error>> {
        let sticker_pack_operation = StickerPackOperation {
            pack_id: Some(pack_id.to_vec()),
            pack_key: Some(pack_key.to_vec()),
            r#type: Some(sticker_pack_operation::Type::Install as i32),
        };

        let unidentified_websocket = self.unidentified_websocket().await?;
        download_sticker_pack(
            self.store.clone(),
            unidentified_websocket,
            &sticker_pack_operation,
        )
        .await?;

        // Sync the change with the other devices
        let sync_message = SyncMessage {
            sticker_pack_operation: vec![sticker_pack_operation],
            ..Default::default()
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;

        self.send_message(self.state.data.service_ids.aci(), sync_message, timestamp)
            .await?;

        Ok(())
    }

    /// Removes an installed sticker pack
    pub async fn remove_sticker_pack(
        &mut self,
        pack_id: &[u8],
        pack_key: &[u8],
    ) -> Result<(), Error<S::Error>> {
        // Sync the change with the other clients
        let sync_message = SyncMessage {
            sticker_pack_operation: vec![StickerPackOperation {
                pack_id: Some(pack_id.to_vec()),
                pack_key: Some(pack_key.to_vec()), // The pack key might not be neccesary in the message
                r#type: Some(sticker_pack_operation::Type::Remove as i32),
            }],
            ..Default::default()
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;

        self.send_message(self.state.data.service_ids.aci(), sync_message, timestamp)
            .await?;

        self.store.remove_sticker_pack(pack_id).await?;

        Ok(())
    }

    pub async fn send_session_reset(
        &mut self,
        recipient: &ServiceId,
        timestamp: u64,
    ) -> Result<(), Error<S::Error>> {
        trace!(recipient = %recipient.service_id_string(), "resetting session for address");

        let mut store = self.store.aci_protocol_store();

        // Archive all sessions with all receiver devices.
        // Note that the "get_sub_device_sessions" does not include the main device, therefore add it.
        // Note that deleting the session is not equivalent to archiving:
        // If we deleted the session, we would also delete the information on the list of devices the peer has, failing message sending.
        for device in store
            .get_sub_device_sessions(recipient)
            .await?
            .into_iter()
            .chain(vec![*DEFAULT_DEVICE_ID])
        {
            let address = recipient
                .aci()
                .expect("Recipient to be given as ACI")
                .to_protocol_address(device)
                .expect("Could not construct protocol address from recipient");
            if let Some(mut session) = store.load_session(&address).await? {
                session.archive_current_state()?;
                store.store_session(&address, &session).await?;
            }
        }

        // TODO: Signal Android also deletes entries in some sender_key_shared table; we don't have such a table yet.
        // Does not seem necessary though.

        // Send a null message.
        let message = NullMessage::generate(&mut rand::rng());
        self.send_message(*recipient, message, timestamp).await?;

        Ok(())
    }

    fn credentials(&self) -> ServiceCredentials {
        self.state.credentials()
    }

    /// Creates a new message sender.
    async fn new_message_sender(&self) -> Result<MessageSender<S::AciStore>, Error<S::Error>> {
        let identified_websocket = self.identified_websocket(false).await?;
        let unidentified_websocket = self.unidentified_websocket().await?;

        let aci_protocol_store = self.store.aci_protocol_store();
        let aci_identity_keypair = aci_protocol_store.get_identity_key_pair().await?;
        let pni_identity_keypair = self
            .store
            .pni_protocol_store()
            .get_identity_key_pair()
            .await?;

        Ok(MessageSender::new(
            identified_websocket,
            unidentified_websocket,
            self.identified_push_service(),
            self.new_service_cipher_aci(),
            aci_protocol_store,
            self.state.data.service_ids.aci,
            self.state.data.service_ids.pni,
            aci_identity_keypair,
            Some(pni_identity_keypair),
            self.state.device_id(),
        ))
    }

    fn new_service_cipher_aci(&self) -> ServiceCipher<S::AciStore> {
        ServiceCipher::new(
            self.store.aci_protocol_store(),
            self.state
                .service_configuration()
                .unidentified_sender_trust_roots,
            ProtocolAddress::new(
                self.state.data.service_ids.aci.to_string(),
                self.state.device_id(),
            ),
        )
    }

    fn new_service_cipher_pni(&self) -> ServiceCipher<S::PniStore> {
        ServiceCipher::new(
            self.store.pni_protocol_store(),
            self.state
                .service_configuration()
                .unidentified_sender_trust_roots,
            ProtocolAddress::new(
                self.state.data.service_ids.pni.to_string(),
                self.state.device_id(),
            ),
        )
    }

    /// Returns the title of a thread (contact or group).
    pub async fn thread_title(&self, thread: &Thread) -> Result<String, Error<S::Error>> {
        match thread {
            Thread::Contact(service_id) => {
                let contact = match self.store.contact_by_id(service_id).await {
                    Ok(contact) => contact,
                    Err(error) => {
                        info!(%error, service_id =% service_id.service_id_string(), "error getting contact by id");
                        None
                    }
                };
                Ok(match contact {
                    Some(contact) => contact.name,
                    None => service_id.service_id_string(),
                })
            }
            Thread::Group(id) => match self.store.group(*id).await? {
                Some(group) => Ok(group.title),
                None => Ok("".to_string()),
            },
        }
    }

    /// Returns how this client was registered, either as a primary or secondary device.
    pub fn registration_type(&self) -> RegistrationType {
        if self.state.data.device_name.is_some() {
            RegistrationType::Secondary
        } else {
            RegistrationType::Primary
        }
    }

    /// As a primary device, link a secondary device.
    pub async fn link_secondary(&mut self, secondary: Url) -> Result<(), Error<S::Error>> {
        // XXX: What happens if secondary device? Possible to use static typing to make this method call impossible in that case?
        if self.registration_type() != RegistrationType::Primary {
            return Err(Error::NotPrimaryDevice);
        }

        let credentials = self.credentials();
        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            self.identified_websocket(false).await?,
            Some(self.state.data.profile_key),
        );

        account_manager
            .link_device(
                &mut rand::rng(),
                secondary,
                &self.store.aci_protocol_store(),
                &self.store.pni_protocol_store(),
                ProvisioningSecrets {
                    credentials,
                    account_entropy_pool: self
                        .account_entropy_pool()
                        .await?
                        .expect("Primary device to always have an account entropy pool"),
                    master_key: self.master_key().await?,
                    ephemeral_backup_key: None,
                    media_root_backup_key: None,
                },
            )
            .await?;
        Ok(())
    }

    /// As a primary device, unlink a secondary device.
    pub async fn unlink_secondary(
        &self,
        device_id: impl TryInto<DeviceId>,
    ) -> Result<(), Error<S::Error>> {
        // secondary devices cannot unlink themselves or other devices, it will fail with an unauthorized error
        if self.registration_type() != RegistrationType::Primary {
            return Err(Error::NotPrimaryDevice);
        }
        self.identified_websocket(false)
            .await?
            .unlink_device(device_id.try_into().map_err(|_| Error::InvalidDeviceId)?)
            .await?;
        Ok(())
    }

    /// As a primary device, list all the devices (including the current device).
    pub async fn devices(&self) -> Result<Vec<DeviceInfo>, Error<S::Error>> {
        let aci_protocol_store = self.store.aci_protocol_store();
        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            self.identified_websocket(false).await?,
            Some(self.state.data.profile_key),
        );

        Ok(account_manager.linked_devices(&aci_protocol_store).await?)
    }
}

fn attachment_ciphertext_size_limit(max_plaintext_size: usize) -> usize {
    let max_plaintext_size = max_plaintext_size as u128;
    // Signal pads to the next 5% privacy bucket, with a minimum padded size of 541 bytes.
    // Adding a full 5% is a conservative upper bound for that bucket.
    let privacy_padded_size = max_plaintext_size
        .saturating_add(max_plaintext_size.div_ceil(ATTACHMENT_PRIVACY_PADDING_DENOMINATOR))
        .max(ATTACHMENT_MIN_PADDED_PLAINTEXT_SIZE);
    // Attachments contain a 16-byte IV, PKCS#7 padded AES-CBC ciphertext, and a 32-byte MAC.
    // PKCS#7 always appends at least one byte, including a full block for block-aligned input.
    let encrypted_size = ATTACHMENT_IV_SIZE
        .saturating_add(
            privacy_padded_size
                .saturating_div(ATTACHMENT_CIPHER_BLOCK_SIZE)
                .saturating_add(1)
                .saturating_mul(ATTACHMENT_CIPHER_BLOCK_SIZE),
        )
        .saturating_add(ATTACHMENT_MAC_SIZE);

    usize::try_from(encrypted_size).unwrap_or(usize::MAX)
}

fn is_valid_attachment_ciphertext_size(ciphertext_size: usize) -> bool {
    let unencrypted_overhead = (ATTACHMENT_IV_SIZE + ATTACHMENT_MAC_SIZE) as usize;
    ciphertext_size >= ATTACHMENT_MIN_CIPHERTEXT_SIZE
        && (ciphertext_size - unencrypted_overhead)
            .is_multiple_of(ATTACHMENT_CIPHER_BLOCK_SIZE as usize)
}

async fn read_attachment_ciphertext<R>(
    reader: &mut R,
    initial_capacity: usize,
    max_ciphertext_size: Option<usize>,
) -> std::io::Result<Option<Vec<u8>>>
where
    R: futures::AsyncRead + Unpin,
{
    let initial_capacity = max_ciphertext_size
        .map(|limit| initial_capacity.min(limit))
        .unwrap_or(initial_capacity);
    let mut ciphertext = Vec::with_capacity(initial_capacity);

    if let Some(max_ciphertext_size) = max_ciphertext_size {
        let read_limit = u64::try_from(max_ciphertext_size)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        reader.take(read_limit).read_to_end(&mut ciphertext).await?;
        if ciphertext.len() > max_ciphertext_size {
            return Ok(None);
        }
    } else {
        reader.read_to_end(&mut ciphertext).await?;
    }

    Ok(Some(ciphertext))
}

/// Set the timestamp in any DataMessage so it matches its envelope's
fn ensure_data_message_timestamp(content_body: &mut ContentBody, timestamp: u64) {
    match content_body {
        ContentBody::DataMessage(message) => {
            message.timestamp = Some(timestamp);
        }
        ContentBody::EditMessage(EditMessage {
            data_message: Some(data_message),
            ..
        }) => {
            data_message.timestamp = Some(timestamp);
        }
        ContentBody::SynchronizeMessage(SyncMessage {
            sent:
                Some(sync_message::Sent {
                    message: Some(data_message),
                    ..
                }),
            ..
        }) => {
            data_message.timestamp = Some(timestamp);
        }
        _ => (),
    }
}

async fn upsert_group<S: Store>(
    store: &S,
    groups_manager: &mut GroupsManager<InMemoryCredentialsCache>,
    master_key_bytes: &[u8],
    revision: &u32,
) -> Result<Option<Group>, Error<S::Error>> {
    let upsert_group = match store.group(master_key_bytes.try_into()?).await {
        Ok(Some(group)) => {
            debug!(group_name =% group.title, "loaded group from local db");
            group.revision < *revision
        }
        Ok(None) => true,
        Err(error) => {
            warn!(%error, "failed to retrieve group from local db");
            true
        }
    };

    if upsert_group {
        debug!("fetching and saving group");
        match groups_manager
            .fetch_encrypted_group(&mut rand::rng(), master_key_bytes)
            .await
        {
            Ok(encrypted_group) => {
                let group = decrypt_group(master_key_bytes, encrypted_group)?;
                if let Err(error) = store.save_group(master_key_bytes.try_into()?, group).await {
                    error!(%error, "failed to save group");
                }
            }
            Err(error) => {
                warn!(%error, "failed to fetch encrypted group")
            }
        }
    }

    Ok(store.group(master_key_bytes.try_into()?).await?)
}

/// Download and decrypt a sticker manifest
async fn download_sticker_pack<C: ContentsStore>(
    mut store: C,
    mut unidentified_websocket: SignalWebSocket<websocket::Unidentified>,
    operation: &StickerPackOperation,
) -> Result<StickerPack, Error<C::ContentsStoreError>> {
    debug!("downloading sticker pack");
    let pack_key = operation.pack_key();
    let pack_id = operation.pack_id();
    let key = derive_key(pack_key)?;

    let mut ciphertext = Vec::new();

    let size_bytes = unidentified_websocket
        .get_sticker_pack_manifest(&hex::encode(pack_id))
        .await?
        .read_to_end(&mut ciphertext)
        .await?;

    trace!(size_bytes, "downloaded encrypted sticker pack manifest");

    decrypt_in_place(key, &mut ciphertext)?;

    let mut sticker_pack_manifest: StickerPackManifest =
        libsignal_service::proto::Pack::decode(ciphertext.as_slice())
            .map_err(ProvisioningError::from)?
            .into();

    for sticker in &mut sticker_pack_manifest.stickers {
        match download_sticker::<C>(&mut unidentified_websocket, pack_id, pack_key, sticker.id)
            .await
        {
            Ok(decrypted_sticker_bytes) => {
                debug!(id = sticker.id, "downloaded sticker");
                sticker.bytes = Some(decrypted_sticker_bytes);
            }
            Err(error) => error!(sticker.id, %error,"failed to download sticker"),
        }
    }

    let sticker_pack = StickerPack {
        id: pack_id.to_vec(),
        key: pack_key.to_vec(),
        manifest: sticker_pack_manifest,
    };

    // save everything in store
    store.add_sticker_pack(&sticker_pack).await?;

    Ok(sticker_pack)
}

/// Downloads and decrypts a single sticker
async fn download_sticker<C: ContentsStore>(
    unidentified_websocket: &mut SignalWebSocket<websocket::Unidentified>,
    pack_id: &[u8],
    pack_key: &[u8],
    sticker_id: u32,
) -> Result<Vec<u8>, Error<C::ContentsStoreError>> {
    let key = derive_key(pack_key)?;

    let mut sticker_stream = unidentified_websocket
        .get_sticker(&hex::encode(pack_id), sticker_id)
        .await?;

    let mut ciphertext = Vec::new();
    let size_bytes = sticker_stream.read_to_end(&mut ciphertext).await?;

    trace!(size_bytes, "downloaded encrypted sticker");

    decrypt_in_place(key, &mut ciphertext)?;

    Ok(ciphertext)
}

/// Save a message into the store.
/// Note that `override_thread` can be used to specify the thread the message will be stored in.
/// This is required when storing outgoing messages, as in this case the appropriate storage place cannot be derived from the message itself.
async fn save_message<S: Store>(
    store: &mut S,
    identified_websocket: &mut websocket::SignalWebSocket<websocket::Identified>,
    contact_updates: &ContactUpdateCoordinator,
    mut profile_workers: Option<&mut ContactProfileWorkerQueue>,
    message: Content,
    override_thread: Option<Thread>,
) -> Result<(), Error<S::Error>> {
    // derive the thread from the message type
    let should_update_contact_profile = override_thread.is_none() && profile_workers.is_some();
    let thread = override_thread.unwrap_or(Thread::try_from(&message)?);
    let profile_update_timestamp = message.timestamp();
    let mut contact_profile_update = None;

    // only save DataMessage and SynchronizeMessage (sent)
    let message = match message.body {
        ContentBody::DecryptionErrorMessage(e) => {
            warn!(error = ?e, "was asked to save a DecryptionErrorMessage; this should not happen");
            None
        }
        ContentBody::NullMessage(_) => Some(message),
        ContentBody::DataMessage(
            ref data_message @ DataMessage {
                ref profile_key, ..
            },
        )
        | ContentBody::SynchronizeMessage(SyncMessage {
            sent:
                Some(sync_message::Sent {
                    message:
                        Some(
                            ref data_message @ DataMessage {
                                ref profile_key, ..
                            },
                        ),
                    ..
                }),
            ..
        }) => {
            // update recipient profile key if changed
            if should_update_contact_profile {
                if let Some(profile_key_bytes) = profile_key.clone().and_then(|p| p.try_into().ok())
                {
                    let sender = message.metadata.sender;
                    let profile_key = ProfileKey::create(profile_key_bytes);
                    debug!(sender = %sender.service_id_string(), "inserting profile key for");

                    contact_profile_update = Some(ContactProfileUpdate {
                        sender,
                        profile_key,
                        observation_timestamp: profile_update_timestamp,
                        expire_timer: data_message.expire_timer.unwrap_or_default(),
                        expire_timer_version: data_message.expire_timer_version.unwrap_or(1),
                    });
                }
            }

            // Note: The expire timer fields of data messages are only for contacts.
            // Expire timers are handled for groups via upsert_group due to a revision change.
            if let Thread::Contact(service_id) = &thread {
                let version = data_message.expire_timer_version.unwrap_or(1);
                let contact_lock = contact_updates.contact_lock(service_id.raw_uuid()).await;
                let _contact_guard = contact_lock.lock().await;
                store
                    .update_expire_timer(
                        &thread,
                        data_message.expire_timer.unwrap_or_default(),
                        version,
                    )
                    .await?;
            }

            match data_message {
                DataMessage {
                    delete:
                        Some(Delete {
                            target_sent_timestamp: Some(ts),
                        }),
                    ..
                } => {
                    // replace an existing message by an empty NullMessage
                    if let Some(mut existing_msg) = store.message(&thread, *ts).await? {
                        existing_msg.metadata.sender = Aci::from(Uuid::nil()).into();
                        existing_msg.body = NullMessage::default().into();
                        store.save_message(&thread, existing_msg).await?;
                        debug!(%thread, ts, "message in thread deleted");
                        None
                    } else {
                        warn!(%thread, ts, "could not find message to delete in thread");
                        None
                    }
                }
                _ => Some(message),
            }
        }
        ContentBody::SynchronizeMessage(SyncMessage {
            delete_for_me: Some(ref delete),
            ..
        }) => {
            // TODO: Conversations, local-only deletes, attachments
            for d in delete.message_deletes.iter().flat_map(|m| &m.messages) {
                let sender = match &d.author {
                    Some(Author::AuthorServiceId(id)) => {
                        ServiceId::parse_from_service_id_string(id)
                    }
                    Some(Author::AuthorServiceIdBinary(id)) => {
                        ServiceId::parse_from_service_id_binary(id)
                    }
                    Some(Author::AuthorE164(_)) => None,
                    None => None,
                };
                let Some(sender) = sender else {
                    tracing::warn!("Could not parse author of delete-for-self message; ignoring.");
                    continue;
                };
                let Some(timestamp) = d.sent_timestamp else {
                    tracing::warn!("Timestamp of delete-for-self message not given; ignoring.");
                    continue;
                };
                let Ok(Some(thread)) = store
                    .thread_for_sender_and_timestamp(&sender, timestamp)
                    .await
                else {
                    tracing::warn!(
                        "Message referenced by delete-for-self message not found; ignoring."
                    );
                    continue;
                };
                // Note: Not marking the message as deleted, like when receiving deletion requests by others.
                // This matches the behavior of Signal Desktop, where the message completely disappears from the timeline.
                let result = store.delete_message(&thread, timestamp).await;
                if !result.is_ok_and(|d| d) {
                    tracing::warn!(
                        "Could not delete message referenced by delete-for-self message; ignoring."
                    );
                }
            }
            None
        }
        ContentBody::EditMessage(EditMessage {
            target_sent_timestamp: Some(_),
            data_message: Some(_),
        })
        | ContentBody::SynchronizeMessage(SyncMessage {
            sent:
                Some(sync_message::Sent {
                    edit_message:
                        Some(EditMessage {
                            target_sent_timestamp: Some(_),
                            data_message: Some(_),
                        }),
                    ..
                }),
            ..
        }) => Some(message),
        ContentBody::CallMessage(_)
        | ContentBody::SynchronizeMessage(SyncMessage {
            call_event: Some(_),
            ..
        }) => Some(message),
        ContentBody::SynchronizeMessage(msg) => {
            debug!(
                ?msg,
                "skipping saving sync message without interesting fields"
            );
            None
        }
        ContentBody::ReceiptMessage(_) => Some(message),
        ContentBody::TypingMessage(msg) => {
            debug!(?msg, "skipping saving typing message");
            None
        }
        ContentBody::StoryMessage(msg) => {
            debug!(?msg, "skipping story message");
            None
        }
        ContentBody::PniSignatureMessage(msg) => {
            debug!(?msg, "skipping PNI signature message");
            None
        }
        ContentBody::EditMessage(msg) => {
            debug!(?msg, "invalid edited");
            None
        }
    };

    if let Some(message) = message {
        store.save_message(&thread, message).await?;
    }

    // Contact data is persisted before optional profile enrichment. One local worker per contact
    // coalesces observations without delaying message delivery.
    if let Some(profile_update) = contact_profile_update {
        let Some(aci) = profile_update.sender.aci() else {
            debug!("not storing profile for PNI contact");
            return Ok(());
        };
        let sender_uuid: Uuid = aci.into();
        contact_updates
            .enqueue_profile_update(sender_uuid, profile_update)
            .await;
        if let Some(profile_workers) = profile_workers.as_deref_mut() {
            profile_workers.start(
                store.clone(),
                identified_websocket.clone(),
                contact_updates.clone(),
                sender_uuid,
            );
        }
    }

    Ok(())
}

fn profile_display_name(profile: &Profile) -> String {
    profile
        .name
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_default()
}

fn merge_synchronized_contact(
    mut synchronized: Contact,
    existing: Option<Contact>,
    stored_profile_key: Option<ProfileKey>,
    stored_profile: Option<&Profile>,
) -> Contact {
    let existing = existing.as_ref();

    if synchronized.name.is_empty() {
        let cached_profile_name = stored_profile
            .map(profile_display_name)
            .filter(|name| !name.is_empty());
        let legacy_profile_name = if stored_profile.is_none() {
            existing
                .filter(|contact| {
                    contact.phone_number.is_none()
                        && contact.profile_key.len() == 32
                        && stored_profile_key.as_ref().is_some_and(|profile_key| {
                            contact.profile_key.as_slice() == profile_key.bytes.as_slice()
                        })
                })
                .map(|contact| contact.name.clone())
                .filter(|name| !name.is_empty())
        } else {
            None
        };
        if let Some(name) = cached_profile_name.or(legacy_profile_name) {
            synchronized.name = name;
        }
    }

    if let Some(existing) = existing {
        synchronized.verified = existing.verified.clone();
    }
    synchronized.profile_key = stored_profile_key
        .map(|profile_key| profile_key.bytes.to_vec())
        .or_else(|| {
            existing
                .filter(|contact| contact.profile_key.len() == 32)
                .map(|contact| contact.profile_key.clone())
        })
        .unwrap_or_default();

    synchronized
}

async fn save_synchronized_contact<S: Store>(
    store: &mut S,
    contact_updates: &ContactUpdateCoordinator,
    contact: libsignal_service::models::Contact,
) -> Result<(), S::Error> {
    let synchronized: Contact = contact.into();
    let uuid = synchronized.uuid;
    let contact_lock = contact_updates.contact_lock(uuid).await;
    let _contact_guard = contact_lock.lock().await;
    let service_id = ServiceId::Aci(Aci::from(uuid));
    let existing = store.contact_by_id(&service_id).await?;
    let stored_profile_key = store.profile_key(&service_id).await?;
    let stored_profile = match (synchronized.name.is_empty(), stored_profile_key) {
        (true, Some(profile_key)) => store.profile(uuid, profile_key).await?,
        _ => None,
    };
    let contact = merge_synchronized_contact(
        synchronized,
        existing,
        stored_profile_key,
        stored_profile.as_ref(),
    );
    store.save_contact(&contact).await
}

fn needs_profile_contact_upsert(
    contact: Option<&Contact>,
    stored_profile_key: Option<&ProfileKey>,
    incoming_profile_key: &ProfileKey,
) -> bool {
    stored_profile_key != Some(incoming_profile_key)
        || contact.is_none_or(|contact| {
            contact.name.is_empty()
                || contact.profile_key.as_slice() != incoming_profile_key.bytes.as_slice()
        })
}

fn merge_profile_contact(
    uuid: Uuid,
    existing: Option<Contact>,
    previous_profile: Option<&Profile>,
    profile: &Profile,
    profile_key: ProfileKey,
    new_contact_timer: u32,
    new_contact_timer_version: u32,
) -> Contact {
    let profile_name = profile_display_name(profile);
    if let Some(mut existing) = existing {
        let previous_profile_name = previous_profile.map(profile_display_name);
        let existing_name_is_profile_owned = existing.phone_number.is_none()
            && previous_profile_name
                .as_ref()
                .is_some_and(|name| !name.is_empty() && name == &existing.name);
        if existing.name.is_empty() || existing_name_is_profile_owned {
            existing.name = profile_name;
        }
        existing.profile_key = profile_key.bytes.to_vec();
        existing
    } else {
        Contact {
            uuid,
            phone_number: None,
            name: profile_name,
            profile_key: profile_key.bytes.to_vec(),
            expire_timer: new_contact_timer,
            expire_timer_version: new_contact_timer_version,
            inbox_position: 0,
            avatar: None,
            verified: Verified::default(),
        }
    }
}

async fn run_contact_profile_worker<S: Store>(
    mut store: S,
    mut identified_websocket: SignalWebSocket<websocket::Identified>,
    contact_updates: ContactUpdateCoordinator,
    sender_uuid: Uuid,
) {
    while let Some(queued) = contact_updates.take_profile_update(sender_uuid).await {
        let observation_timestamp = queued.update.observation_timestamp;
        if let Err(error) = process_contact_profile_update(
            &mut store,
            &mut identified_websocket,
            &contact_updates,
            sender_uuid,
            queued,
        )
        .await
        {
            error!(
                %error,
                %sender_uuid,
                observation_timestamp,
                "failed to update contact profile"
            );
        }
    }
}

async fn process_contact_profile_update<S: Store>(
    store: &mut S,
    identified_websocket: &mut SignalWebSocket<websocket::Identified>,
    contact_updates: &ContactUpdateCoordinator,
    sender_uuid: Uuid,
    queued: QueuedContactProfileUpdate,
) -> Result<(), Error<<S as Store>::Error>> {
    let queued = {
        let contact_lock = contact_updates.contact_lock(sender_uuid).await;
        let _contact_guard = contact_lock.lock().await;
        let Some(queued) = contact_updates
            .coalesce_current_profile_update(sender_uuid, queued)
            .await
        else {
            debug!(%sender_uuid, "ignoring superseded contact profile update");
            return Ok(());
        };
        let update = &queued.update;
        let sender = update.sender;
        let profile_key = update.profile_key;
        let existing = store.contact_by_id(&sender).await?;
        let stored_profile_key = store.profile_key(&sender).await?;
        if !needs_profile_contact_upsert(
            existing.as_ref(),
            stored_profile_key.as_ref(),
            &profile_key,
        ) {
            return Ok(());
        }

        let previous_profile = match stored_profile_key {
            Some(stored_profile_key) => store.profile(sender_uuid, stored_profile_key).await?,
            None => None,
        };
        let profile_key_is_unchanged = stored_profile_key.as_ref() == Some(&profile_key);
        let latest_contact = store.contact_by_id(&sender).await?;

        if profile_key_is_unchanged {
            if let Some(profile) = previous_profile.as_ref() {
                let profile_name = profile_display_name(profile);
                if latest_contact.as_ref().is_some_and(|contact| {
                    contact.name.is_empty()
                        && profile_name.is_empty()
                        && contact.profile_key.as_slice() == profile_key.bytes.as_slice()
                }) {
                    return Ok(());
                }

                let Some(queued) = contact_updates
                    .coalesce_current_profile_update(sender_uuid, queued.clone())
                    .await
                else {
                    return Ok(());
                };
                let update = &queued.update;
                let contact = merge_profile_contact(
                    sender_uuid,
                    latest_contact,
                    previous_profile.as_ref(),
                    profile,
                    update.profile_key,
                    update.expire_timer,
                    update.expire_timer_version,
                );
                store.save_contact(&contact).await?;
                return Ok(());
            }

            if let Some(mut contact) = latest_contact {
                if !contact.name.is_empty() {
                    if contact_updates
                        .coalesce_current_profile_update(sender_uuid, queued.clone())
                        .await
                        .is_none()
                    {
                        return Ok(());
                    }
                    contact.profile_key = profile_key.bytes.to_vec();
                    store.save_contact(&contact).await?;
                    return Ok(());
                }
            }
        }

        queued
    };

    let sender = queued.update.sender;
    let Some(aci) = sender.aci() else {
        return Ok(());
    };
    let profile_key = queued.update.profile_key;
    let encrypted_profile = match tokio::time::timeout(
        CONTACT_PROFILE_FETCH_TIMEOUT,
        identified_websocket.retrieve_profile_by_id(aci, Some(profile_key)),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => {
            warn!(%sender_uuid, "timed out retrieving contact profile");
            return Ok(());
        }
    };
    let profile = ProfileCipher::new(profile_key).decrypt(encrypted_profile)?;

    let contact_lock = contact_updates.contact_lock(sender_uuid).await;
    let _contact_guard = contact_lock.lock().await;
    let Some(queued) = contact_updates
        .coalesce_current_profile_update(sender_uuid, queued)
        .await
    else {
        debug!(%sender_uuid, "discarding superseded contact profile response");
        return Ok(());
    };
    let update = &queued.update;
    let stored_profile_key = store.profile_key(&update.sender).await?;
    let previous_profile = match stored_profile_key {
        Some(stored_profile_key) => store.profile(sender_uuid, stored_profile_key).await?,
        None => None,
    };
    let Some(queued) = contact_updates
        .coalesce_current_profile_update(sender_uuid, queued)
        .await
    else {
        debug!(%sender_uuid, "discarding superseded contact profile response");
        return Ok(());
    };
    let update = &queued.update;
    store
        .save_profile(sender_uuid, update.profile_key, profile.clone())
        .await?;

    let latest_contact = store.contact_by_id(&update.sender).await?;
    let contact = merge_profile_contact(
        sender_uuid,
        latest_contact,
        previous_profile.as_ref(),
        &profile,
        update.profile_key,
        update.expire_timer,
        update.expire_timer_version,
    );

    info!(%sender_uuid, "saved contact profile");
    store.save_contact(&contact).await?;
    Ok(())
}

async fn set_account_attributes<S: Store>(
    account_manager: &mut AccountManager,
    store: &S,
    data: &RegistrationData,
) -> Result<(), Error<S::Error>> {
    trace!("setting account attributes");

    let pni_registration_id = data.pni_registration_id.ok_or(Error::RelinkNecessary)?;

    let name = if let Some(device_name) = data.device_name() {
        let aci_key_pair = store.aci_protocol_store().get_identity_key_pair().await?;
        let mut rng = rng();
        Some(encrypt_device_name(
            &mut rng,
            device_name,
            aci_key_pair.identity_key(),
        )?)
    } else {
        None
    };

    account_manager
        .set_account_attributes(AccountAttributes {
            fetches_messages: true,
            registration_id: data.registration_id,
            pni_registration_id,
            name,
            registration_lock: None,
            unidentified_access_key: Some(data.profile_key.derive_access_key().to_vec()),
            unrestricted_unidentified_access: false,
            capabilities: DeviceCapabilities {
                storage: true,
                transfer: false,
                attachment_backfill: false,
                spqr: true,
                profiles_v2: false,
                username_change_sync_message: true,
            },
            discoverable_by_phone_number: true,
            pin: None,
            recovery_password: None,
        })
        .await?;

    trace!("done setting account attributes");
    Ok(())
}

async fn register_pre_keys<S: Store>(
    store: &S,
    account_manager: &mut AccountManager,
) -> Result<(), Error<S::Error>> {
    trace!("registering pre keys");

    account_manager
        .update_pre_key_bundle(&mut store.aci_protocol_store(), ServiceIdKind::Aci, true)
        .await?;

    account_manager
        .update_pre_key_bundle(&mut store.pni_protocol_store(), ServiceIdKind::Pni, true)
        .await?;

    trace!("registered pre keys");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::Cursor;
    use libsignal_service::attachment_cipher::encrypt_in_place;
    use libsignal_service::groups_v2::{Group as ServiceGroup, Member as ServiceMember, Role};
    use libsignal_service::proto::manifest_record::{identifier::Type, Identifier};
    use libsignal_service::proto::{
        GroupChange as ProtoGroupChange, GroupV2Record, ManifestRecord, StorageRecord,
    };
    use reqwest::header::{HeaderName, HeaderValue};

    fn aci(value: u128) -> Aci {
        Aci::from(Uuid::from_u128(value))
    }

    fn signal_sender_ciphertext_size(plaintext_size: usize) -> usize {
        let padded_size = std::cmp::max(
            ATTACHMENT_MIN_PADDED_PLAINTEXT_SIZE as usize,
            1.05f64
                .powf((plaintext_size as f64).log(1.05).ceil())
                .floor() as usize,
        );
        ATTACHMENT_IV_SIZE as usize
            + (padded_size / ATTACHMENT_CIPHER_BLOCK_SIZE as usize + 1)
                * ATTACHMENT_CIPHER_BLOCK_SIZE as usize
            + ATTACHMENT_MAC_SIZE as usize
    }

    #[test]
    fn attachment_ciphertext_limit_includes_signal_padding_and_encryption_overhead() {
        assert_eq!(attachment_ciphertext_size_limit(0), 592);
        assert_eq!(attachment_ciphertext_size_limit(1), 592);
        assert_eq!(
            attachment_ciphertext_size_limit(25 * 1024 * 1024),
            27_525_184
        );

        for plaintext_size in [
            0,
            1,
            540,
            541,
            542,
            1024,
            100 * 1024,
            25 * 1024 * 1024,
            u32::MAX as usize,
        ] {
            assert!(
                signal_sender_ciphertext_size(plaintext_size)
                    <= attachment_ciphertext_size_limit(plaintext_size),
                "ciphertext bound was too small for {plaintext_size} plaintext bytes"
            );
        }

        let mut exponent = 0;
        loop {
            let boundary = 1.05f64.powi(exponent);
            if boundary > u32::MAX as f64 + 2.0 {
                break;
            }
            let first_candidate = boundary.floor() as i64 - 2;
            let last_candidate = boundary.ceil() as i64 + 2;
            for plaintext_size in first_candidate..=last_candidate {
                if !(0..=u32::MAX as i64).contains(&plaintext_size) {
                    continue;
                }
                let plaintext_size = plaintext_size as usize;
                assert!(
                    signal_sender_ciphertext_size(plaintext_size)
                        <= attachment_ciphertext_size_limit(plaintext_size),
                    "ciphertext bound was too small at bucket edge {plaintext_size}"
                );
            }
            exponent += 1;
        }
    }

    #[test]
    fn attachment_ciphertext_framing_rejects_lengths_that_cannot_be_decrypted() {
        for ciphertext_size in [0, 31, 32, 47, 48, 63, 65, 79] {
            assert!(!is_valid_attachment_ciphertext_size(ciphertext_size));
        }
        for ciphertext_size in [64, 80, 96, 592] {
            assert!(is_valid_attachment_ciphertext_size(ciphertext_size));
        }
    }

    #[tokio::test]
    async fn bounded_attachment_reader_stops_after_first_excess_byte() {
        let max_ciphertext_size = 64;
        let mut reader = Cursor::new(vec![7; max_ciphertext_size + 32]);

        let ciphertext = read_attachment_ciphertext(&mut reader, 0, Some(max_ciphertext_size))
            .await
            .unwrap();

        assert!(ciphertext.is_none());
        assert_eq!(reader.position(), (max_ciphertext_size + 1) as u64);
    }

    #[tokio::test]
    async fn bounded_attachment_reader_accepts_the_exact_limit() {
        let expected = vec![7; 64];
        let mut reader = Cursor::new(expected.clone());

        let ciphertext = read_attachment_ciphertext(&mut reader, 0, Some(expected.len()))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(ciphertext, expected);
        assert_eq!(reader.position(), expected.len() as u64);
    }

    #[tokio::test]
    async fn bounded_attachment_reader_preserves_digest_and_decryption_input() {
        let key = [9; 64];
        let plaintext = b"bounded attachment";
        let mut encrypted = plaintext.to_vec();
        encrypted.resize(ATTACHMENT_MIN_PADDED_PLAINTEXT_SIZE as usize, 0);
        encrypt_in_place([7; 16], key, &mut encrypted);
        let expected_digest = sha2::Sha256::digest(&encrypted);
        let ciphertext_limit = attachment_ciphertext_size_limit(plaintext.len());
        let mut reader = Cursor::new(encrypted);

        let mut downloaded = read_attachment_ciphertext(&mut reader, 0, Some(ciphertext_limit))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(sha2::Sha256::digest(&downloaded), expected_digest);
        decrypt_in_place(key, &mut downloaded).unwrap();
        downloaded.truncate(plaintext.len());
        assert_eq!(downloaded, plaintext);
    }

    fn contact(name: &str, profile_key: Vec<u8>) -> Contact {
        Contact {
            uuid: Uuid::from_u128(1),
            phone_number: None,
            name: name.into(),
            verified: Verified::default(),
            profile_key,
            expire_timer: 10,
            expire_timer_version: 2,
            inbox_position: 3,
            avatar: None,
        }
    }

    fn profile(name: Option<(&str, Option<&str>)>) -> Profile {
        Profile {
            name: name.map(|(given_name, family_name)| {
                libsignal_service::profile_name::ProfileName {
                    given_name: given_name.into(),
                    family_name: family_name.map(Into::into),
                }
            }),
            ..Profile::default()
        }
    }

    fn contact_profile_update(
        uuid: Uuid,
        observation_timestamp: u64,
        profile_key: ProfileKey,
    ) -> ContactProfileUpdate {
        ContactProfileUpdate {
            sender: ServiceId::Aci(Aci::from(uuid)),
            profile_key,
            observation_timestamp,
            expire_timer: 10,
            expire_timer_version: 2,
        }
    }

    #[tokio::test]
    async fn profile_update_order_uses_observation_sequence_not_content_timestamp() {
        let coordinator = ContactUpdateCoordinator::default();
        let uuid = Uuid::from_u128(1);
        let first = contact_profile_update(uuid, u64::MAX, ProfileKey::create([7; 32]));
        let later = contact_profile_update(uuid, 1, ProfileKey::create([8; 32]));

        coordinator.enqueue_profile_update(uuid, first).await;
        coordinator.enqueue_profile_update(uuid, later).await;
        let queued = coordinator.take_profile_update(uuid).await.unwrap();

        assert_eq!(queued.update.observation_timestamp, 1);
        assert_eq!(queued.update.profile_key.bytes, [8; 32]);
        assert_eq!(queued.observation.sequence, 2);
    }

    #[tokio::test]
    async fn same_key_profile_updates_coalesce_to_the_latest_payload() {
        let coordinator = ContactUpdateCoordinator::default();
        let uuid = Uuid::from_u128(1);
        let profile_key = ProfileKey::create([7; 32]);
        let first = contact_profile_update(uuid, 20, profile_key);
        let mut latest = contact_profile_update(uuid, 21, profile_key);
        latest.expire_timer = 30;
        latest.expire_timer_version = 4;

        coordinator.enqueue_profile_update(uuid, first).await;
        let first_queued = coordinator.take_profile_update(uuid).await.unwrap();
        coordinator.enqueue_profile_update(uuid, latest).await;
        let coalesced = coordinator
            .coalesce_current_profile_update(uuid, first_queued)
            .await
            .unwrap();

        assert_eq!(coalesced.update.observation_timestamp, 21);
        assert_eq!(coalesced.update.expire_timer, 30);
        assert_eq!(coalesced.update.expire_timer_version, 4);
        assert_eq!(coalesced.observation.sequence, 2);
        assert!(coordinator.take_profile_update(uuid).await.is_none());
    }

    #[test]
    fn queue_empty_waits_for_profile_workers_and_restart_has_no_active_flag() {
        let workers = ContactProfileWorkerQueue::default();
        assert!(workers.is_empty());

        workers
            .workers
            .push(future::pending::<Uuid>().boxed_local());
        assert!(!workers.is_empty());

        drop(workers);
        assert!(ContactProfileWorkerQueue::default().is_empty());
    }

    #[tokio::test]
    async fn contact_updates_share_a_lock_and_supersede_inflight_profiles() {
        let coordinator = ContactUpdateCoordinator::default();
        let uuid = Uuid::from_u128(1);
        let old = contact_profile_update(uuid, 20, ProfileKey::create([7; 32]));
        let new = contact_profile_update(uuid, 21, ProfileKey::create([8; 32]));
        coordinator.enqueue_profile_update(uuid, old).await;
        let old_queued = coordinator.take_profile_update(uuid).await.unwrap();
        let old_lock = coordinator.contact_lock(uuid).await;
        let new_lock = coordinator.contact_lock(uuid).await;
        let old_guard = old_lock.lock().await;

        assert!(Arc::ptr_eq(&old_lock, &new_lock));
        assert!(new_lock.try_lock().is_err());
        let mut enqueue_new = Box::pin(coordinator.enqueue_profile_update(uuid, new));
        assert!(matches!(
            futures::poll!(enqueue_new.as_mut()),
            std::task::Poll::Pending
        ));

        drop(old_guard);
        enqueue_new.await;
        assert!(coordinator
            .coalesce_current_profile_update(uuid, old_queued)
            .await
            .is_none());
        let new_queued = coordinator.take_profile_update(uuid).await.unwrap();
        assert_eq!(new_queued.update.profile_key.bytes, [8; 32]);
        assert!(new_lock.try_lock().is_ok());
    }

    #[test]
    fn empty_sync_uses_cached_profile_name_and_canonical_key() {
        let profile_key = ProfileKey::create([7; 32]);
        let cached_profile = profile(Some(("Profile", Some("Name"))));
        let phone_number = "+12025550123".parse::<PhoneNumber>().unwrap();
        let mut synchronized = contact("", Vec::new());
        synchronized.phone_number = Some(phone_number.clone());
        synchronized.expire_timer = 20;
        synchronized.expire_timer_version = 4;
        synchronized.inbox_position = 9;
        let mut existing = contact("Legacy Profile", profile_key.bytes.to_vec());
        existing.verified = Verified {
            identity_key: Some(vec![5; 33]),
            ..Verified::default()
        };
        let expected_verified = existing.verified.clone();

        let merged = merge_synchronized_contact(
            synchronized,
            Some(existing),
            Some(profile_key),
            Some(&cached_profile),
        );

        assert_eq!(merged.name, "Profile Name");
        assert_eq!(merged.profile_key, profile_key.bytes);
        assert_eq!(merged.phone_number, Some(phone_number));
        assert_eq!(merged.expire_timer, 20);
        assert_eq!(merged.expire_timer_version, 4);
        assert_eq!(merged.inbox_position, 9);
        assert_eq!(merged.verified, expected_verified);
    }

    #[test]
    fn nonempty_synchronized_name_wins_over_profile() {
        let profile_key = ProfileKey::create([7; 32]);
        let cached_profile = profile(Some(("Profile", None)));
        let synchronized = contact("Address Book", Vec::new());

        let merged = merge_synchronized_contact(
            synchronized,
            Some(contact("Old Profile", profile_key.bytes.to_vec())),
            Some(profile_key),
            Some(&cached_profile),
        );

        assert_eq!(merged.name, "Address Book");
        assert_eq!(merged.profile_key, profile_key.bytes);
    }

    #[test]
    fn legacy_empty_sync_keeps_a_profile_fallback_without_a_cached_profile() {
        let profile_key = ProfileKey::create([7; 32]);

        let merged = merge_synchronized_contact(
            contact("", Vec::new()),
            Some(contact("Legacy Profile", profile_key.bytes.to_vec())),
            Some(profile_key),
            None,
        );

        assert_eq!(merged.name, "Legacy Profile");
        assert_eq!(merged.profile_key, profile_key.bytes);
    }

    #[test]
    fn synchronized_contact_prefers_canonical_key_and_drops_a_malformed_orphan() {
        let profile_key = ProfileKey::create([7; 32]);
        let canonical = merge_synchronized_contact(
            contact("Synced", Vec::new()),
            Some(contact("Existing", vec![8; 32])),
            Some(profile_key),
            None,
        );
        let malformed_orphan = merge_synchronized_contact(
            contact("Synced", Vec::new()),
            Some(contact("Existing", vec![8; 31])),
            None,
            None,
        );

        assert_eq!(canonical.profile_key, profile_key.bytes);
        assert!(malformed_orphan.profile_key.is_empty());
    }

    #[test]
    fn profile_refresh_updates_a_known_profile_name() {
        let old_profile = profile(Some(("Old", Some("Profile"))));
        let new_profile = profile(Some(("New", Some("Profile"))));
        let new_profile_key = ProfileKey::create([8; 32]);

        let merged = merge_profile_contact(
            Uuid::from_u128(1),
            Some(contact("Old Profile", vec![7; 32])),
            Some(&old_profile),
            &new_profile,
            new_profile_key,
            30,
            4,
        );

        assert_eq!(merged.name, "New Profile");
        assert_eq!(merged.profile_key, new_profile_key.bytes);
        assert_eq!(merged.expire_timer, 10);
        assert_eq!(merged.expire_timer_version, 2);
    }

    #[test]
    fn profile_refresh_preserves_synchronized_contact_fields() {
        let old_profile = profile(Some(("Address", Some("Book"))));
        let new_profile = profile(Some(("New", Some("Profile"))));
        let new_profile_key = ProfileKey::create([8; 32]);
        let phone_number = "+12025550123".parse::<PhoneNumber>().unwrap();
        let mut existing = contact("Address Book", vec![7; 32]);
        existing.phone_number = Some(phone_number.clone());
        existing.expire_timer = 60;
        existing.expire_timer_version = 6;
        existing.inbox_position = 12;
        existing.avatar = Some(libsignal_service::models::Attachment {
            content_type: "image/png".into(),
            reader: bytes::Bytes::from_static(b"avatar"),
        });
        existing.verified = Verified {
            identity_key: Some(vec![6; 33]),
            ..Verified::default()
        };
        let expected_verified = existing.verified.clone();

        let merged = merge_profile_contact(
            Uuid::from_u128(1),
            Some(existing),
            Some(&old_profile),
            &new_profile,
            new_profile_key,
            30,
            4,
        );

        assert_eq!(merged.name, "Address Book");
        assert_eq!(merged.phone_number, Some(phone_number));
        assert_eq!(merged.profile_key, new_profile_key.bytes);
        assert_eq!(merged.expire_timer, 60);
        assert_eq!(merged.expire_timer_version, 6);
        assert_eq!(merged.inbox_position, 12);
        assert_eq!(merged.verified, expected_verified);
        let avatar = merged.avatar.unwrap();
        assert_eq!(avatar.content_type, "image/png");
        assert_eq!(avatar.reader, bytes::Bytes::from_static(b"avatar"));
    }

    #[test]
    fn profile_contact_upsert_detects_empty_names_and_key_drift() {
        let profile_key = ProfileKey::create([7; 32]);
        let other_profile_key = ProfileKey::create([8; 32]);
        let complete = contact("Profile", profile_key.bytes.to_vec());
        let empty = contact("", profile_key.bytes.to_vec());
        let stale_duplicate = contact("Profile", other_profile_key.bytes.to_vec());

        assert!(needs_profile_contact_upsert(
            None,
            Some(&profile_key),
            &profile_key
        ));
        assert!(needs_profile_contact_upsert(
            Some(&empty),
            Some(&profile_key),
            &profile_key
        ));
        assert!(needs_profile_contact_upsert(
            Some(&stale_duplicate),
            Some(&profile_key),
            &profile_key
        ));
        assert!(needs_profile_contact_upsert(
            Some(&complete),
            None,
            &profile_key
        ));
        assert!(needs_profile_contact_upsert(
            Some(&complete),
            Some(&other_profile_key),
            &profile_key
        ));
        assert!(!needs_profile_contact_upsert(
            Some(&complete),
            Some(&profile_key),
            &profile_key
        ));
    }

    #[test]
    fn profile_contact_creation_uses_profile_name_and_message_timer() {
        let profile = profile(Some(("New", Some("Contact"))));
        let profile_key = ProfileKey::create([7; 32]);

        let merged =
            merge_profile_contact(Uuid::from_u128(1), None, None, &profile, profile_key, 30, 4);

        assert_eq!(merged.name, "New Contact");
        assert_eq!(merged.profile_key, profile_key.bytes);
        assert_eq!(merged.expire_timer, 30);
        assert_eq!(merged.expire_timer_version, 4);
    }

    fn service_group(members: &[Aci]) -> ServiceGroup {
        ServiceGroup {
            title: "test group".into(),
            avatar: String::new(),
            disappearing_messages_timer: None,
            access_control: None,
            version: 4,
            members: members
                .iter()
                .copied()
                .map(|aci| ServiceMember {
                    aci,
                    role: Role::Default,
                    profile_key: ProfileKey::create([3; 32]),
                    joined_at_version: 1,
                    label: None,
                    label_emoji: None,
                })
                .collect(),
            members_pending_profile_key: Vec::new(),
            members_pending_admin_approval: Vec::new(),
            invite_link_password: Vec::new(),
            description_text: None,
            announcements_only: false,
            members_banned: Vec::new(),
        }
    }

    fn timestamp_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(SIGNAL_TIMESTAMP_HEADER),
            HeaderValue::from_static("123456789"),
        );
        headers
    }

    fn storage_group_record(value: u8) -> StorageRecord {
        StorageRecord {
            record: Some(storage_record::Record::GroupV2(GroupV2Record {
                master_key: vec![value; 32],
                ..Default::default()
            })),
        }
    }

    #[test]
    fn selects_only_group_v2_storage_items() {
        let manifest = ManifestRecord {
            identifiers: vec![
                Identifier {
                    raw: vec![1],
                    r#type: Type::Contact as i32,
                },
                Identifier {
                    raw: vec![2],
                    r#type: Type::Groupv2 as i32,
                },
                Identifier {
                    raw: vec![3],
                    r#type: Type::Groupv1 as i32,
                },
            ],
            ..ManifestRecord::default()
        };

        assert_eq!(storage_group_item_keys(&manifest).unwrap(), vec![vec![2]]);
    }

    #[test]
    fn rejects_duplicate_group_keys_in_manifest() {
        let manifest = ManifestRecord {
            identifiers: vec![
                Identifier {
                    raw: vec![2],
                    r#type: Type::Groupv2 as i32,
                },
                Identifier {
                    raw: vec![2],
                    r#type: Type::Groupv2 as i32,
                },
            ],
            ..ManifestRecord::default()
        };

        assert_eq!(
            storage_group_item_keys(&manifest),
            Err(StorageGroupSnapshotError::DuplicateManifestKey)
        );
    }

    #[test]
    fn accepts_reordered_exact_storage_response_keys() {
        let requested = vec![vec![1], vec![2]];
        let records = match_storage_group_records(
            &requested,
            vec![
                (vec![2], storage_group_record(2)),
                (vec![1], storage_group_record(1)),
            ],
        )
        .unwrap();

        let master_keys = records
            .into_iter()
            .map(|record| match record.record.unwrap() {
                storage_record::Record::GroupV2(group) => group.master_key,
                _ => unreachable!(),
            })
            .collect::<Vec<_>>();
        assert_eq!(master_keys, vec![vec![1; 32], vec![2; 32]]);
    }

    #[test]
    fn rejects_incomplete_or_unrequested_storage_response_keys() {
        let requested = vec![vec![1], vec![2]];

        assert_eq!(
            match_storage_group_records(&requested, vec![(vec![1], storage_group_record(1))]),
            Err(StorageGroupSnapshotError::ResponseKeySetMismatch)
        );
        assert_eq!(
            match_storage_group_records(
                &requested,
                vec![
                    (vec![1], storage_group_record(1)),
                    (vec![2], storage_group_record(2)),
                    (vec![3], storage_group_record(3)),
                ]
            ),
            Err(StorageGroupSnapshotError::ResponseKeySetMismatch)
        );
        assert_eq!(
            match_storage_group_records(
                &requested,
                vec![
                    (vec![1], storage_group_record(1)),
                    (vec![1], storage_group_record(1)),
                ]
            ),
            Err(StorageGroupSnapshotError::ResponseKeySetMismatch)
        );
    }

    #[test]
    fn filters_snapshots_to_active_self_membership() {
        let own = aci(1);
        assert!(group_has_member(&service_group(&[own, aci(2)]), own));
        assert!(!group_has_member(&service_group(&[aci(2)]), own));
        assert!(!group_has_member(&service_group(&[]), own));
    }

    #[test]
    fn confirms_leave_when_authoritative_group_is_inaccessible() {
        let own = aci(1);

        assert!(confirmed_group_after_leave(None, own).unwrap().is_none());
    }

    #[test]
    fn confirms_leave_from_authoritative_nonmembership() {
        let own = aci(1);
        let other = aci(2);
        let confirmed = confirmed_group_after_leave(Some(service_group(&[other])), own)
            .unwrap()
            .unwrap();

        assert_eq!(confirmed.members.len(), 1);
        assert_eq!(confirmed.members[0].aci, other);
    }

    #[test]
    fn rejects_leave_confirmation_while_account_is_still_a_member() {
        let own = aci(1);

        assert!(matches!(
            confirmed_group_after_leave(Some(service_group(&[own])), own),
            Err(GroupLeaveConfirmationError::StillMember)
        ));
    }

    #[test]
    fn identifies_only_stale_stored_group_keys() {
        let active = HashSet::from([[1; 32], [3; 32]]);
        assert_eq!(
            stale_group_keys([[1; 32], [2; 32], [3; 32]], &active),
            vec![[2; 32]]
        );
    }

    #[test]
    fn keeps_cached_manifest_absent_group_when_still_active() {
        let manifest_key = [1; 32];
        let cached_key = [2; 32];
        let candidates = group_candidate_keys([manifest_key], [cached_key]);
        assert_eq!(candidates, HashSet::from([manifest_key, cached_key]));

        let own = aci(1);
        let active = active_group_from_snapshot(cached_key, service_group(&[own]), own).unwrap();
        let active_keys = HashSet::from([active.0]);
        assert!(stale_group_keys([cached_key], &active_keys).is_empty());
    }

    #[test]
    fn prunes_cached_manifest_absent_group_after_authoritative_nonmembership() {
        let cached_key = [2; 32];
        let candidates = group_candidate_keys([], [cached_key]);
        assert_eq!(candidates, HashSet::from([cached_key]));

        let own = aci(1);
        assert!(active_group_from_snapshot(cached_key, service_group(&[aci(2)]), own).is_none());
        assert_eq!(
            stale_group_keys([cached_key], &HashSet::new()),
            vec![cached_key]
        );
    }

    #[test]
    fn builds_and_decodes_a_leave_change() {
        assert_eq!(GROUPS_V2_ENDPOINT, "/v2/groups/");
        let master_key = [9; 32];
        let secret_params =
            GroupSecretParams::derive_from_master_key(GroupMasterKey::new(master_key));
        let operations = GroupOperations::new(secret_params);
        let own = aci(1);
        let own_uuid: Uuid = own.into();
        let request = build_leave_group_actions(&operations, own, 8).unwrap();

        assert_eq!(request.source_user_id.len(), 16);
        assert_eq!(request.source_user_id, own_uuid.as_bytes());
        assert!(request.group_id.is_empty());
        assert_eq!(request.version, 8);
        assert_eq!(request.delete_members.len(), 1);

        // The service binds the response to the group and encrypts the editor
        // before signing it. Recreate that response shape for decoder coverage.
        let mut response_actions = request;
        response_actions.group_id = secret_params.get_group_identifier().to_vec();
        response_actions.source_user_id =
            response_actions.delete_members[0].deleted_user_id.clone();
        let response = ProtoGroupChange {
            actions: response_actions.encode_to_vec(),
            server_signature: vec![0; 64],
            change_epoch: 0,
        };
        let decoded = operations.decrypt_group_change(response).unwrap();
        assert!(is_expected_leave_change(
            &decoded,
            secret_params.get_group_identifier(),
            own,
            8
        ));
        assert!(!is_expected_leave_change(
            &decoded,
            secret_params.get_group_identifier(),
            own,
            9
        ));
    }

    #[test]
    fn reads_signal_group_change_timestamp() {
        let mut headers = timestamp_headers();
        assert_eq!(signal_response_timestamp(&headers), Some(123_456_789));

        headers.insert(
            HeaderName::from_static(SIGNAL_TIMESTAMP_HEADER),
            HeaderValue::from_static("invalid"),
        );
        assert_eq!(signal_response_timestamp(&headers), None);
    }

    #[test]
    fn classifies_authoritative_group_responses() {
        let headers = timestamp_headers();
        assert_eq!(
            classify_authoritative_group_response(StatusCode::OK, &headers).unwrap(),
            AuthoritativeGroupResponse::Current
        );
        assert_eq!(
            classify_authoritative_group_response(StatusCode::FORBIDDEN, &headers).unwrap(),
            AuthoritativeGroupResponse::Inactive
        );
        assert_eq!(
            classify_authoritative_group_response(StatusCode::NOT_FOUND, &headers).unwrap(),
            AuthoritativeGroupResponse::Inactive
        );
        assert_eq!(
            classify_authoritative_group_response(StatusCode::UNAUTHORIZED, &headers).unwrap(),
            AuthoritativeGroupResponse::Error
        );
        assert_eq!(
            classify_authoritative_group_response(StatusCode::LOCKED, &headers).unwrap(),
            AuthoritativeGroupResponse::Error
        );
        assert_eq!(
            classify_authoritative_group_response(StatusCode::INTERNAL_SERVER_ERROR, &headers)
                .unwrap(),
            AuthoritativeGroupResponse::Error
        );
    }

    #[test]
    fn rejects_departure_without_a_valid_timestamp() {
        assert!(matches!(
            classify_authoritative_group_response(StatusCode::FORBIDDEN, &HeaderMap::new()),
            Err(ServiceError::InvalidFrame { .. })
        ));
        assert!(matches!(
            classify_authoritative_group_response(StatusCode::NOT_FOUND, &HeaderMap::new()),
            Err(ServiceError::InvalidFrame { .. })
        ));

        let mut headers = timestamp_headers();
        headers.insert(
            HeaderName::from_static(SIGNAL_TIMESTAMP_HEADER),
            HeaderValue::from_static("invalid"),
        );
        assert!(matches!(
            classify_authoritative_group_response(StatusCode::FORBIDDEN, &headers),
            Err(ServiceError::InvalidFrame { .. })
        ));
    }

    #[test]
    fn requires_a_group_in_the_current_state_response() {
        assert!(matches!(
            group_from_response(GroupResponse::default()),
            Err(ServiceError::GroupsV2Error)
        ));
        assert!(group_from_response(GroupResponse {
            group: Some(libsignal_service::proto::Group::default()),
            ..Default::default()
        })
        .is_ok());
    }
}
