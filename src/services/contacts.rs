//! Contact discovery by phone number, profile lookups, friend list retrieval,
//! friend requests, aliases, and blocklist controls.

use reqwest::Method;
use serde_json::{json, Value};

use crate::{
    error::{ZaloxError, ZaloxResult},
    session::ZaloxSession,
    types::AvatarPreset,
};

/// Domain facade for contacts, user profiles, and relationship management.
#[derive(Clone)]
pub struct ContactsService {
    session: ZaloxSession,
}

impl ContactsService {
    pub(crate) fn new(session: ZaloxSession) -> Self {
        Self { session }
    }

    /// Searches a Zalo user profile by phone number (automatically normalizes `0xxx` -> `84xxx` for VN).
    pub async fn find_by_phone(&self, phone: &str, avatar: AvatarPreset) -> ZaloxResult<Value> {
        let trimmed = phone.trim();
        if trimmed.is_empty() {
            return Err(ZaloxError::InvalidInput(
                "Phone number must not be empty".into(),
            ));
        }

        let normalized = if trimmed.starts_with('0') && self.session.core.language == "vi" {
            format!("84{}", &trimmed[1..])
        } else {
            trimmed.trim_start_matches('+').to_owned()
        };

        let base = format!(
            "{}/api/friend/profile/get",
            self.session.core.services.friend_base()
        );
        let url = self
            .session
            .core
            .gateway
            .build_endpoint_url(&base, &[], true)?;
        let params = json!({
            "phone": normalized,
            "avatar_size": avatar as u16,
            "language": self.session.core.language,
            "imei": self.session.core.imei,
            "reqSrc": 40,
        });

        self.session
            .core
            .gateway
            .request_encrypted_query(
                Method::GET,
                url,
                &self.session.core.cipher,
                &params,
                true,
                true,
            )
            .await
    }

    /// Fetches detailed profiles for one or more Zalo user IDs.
    pub async fn fetch_profiles(
        &self,
        user_ids: &[String],
        avatar: AvatarPreset,
    ) -> ZaloxResult<Value> {
        if user_ids.is_empty() {
            return Err(ZaloxError::InvalidInput(
                "user_ids list must not be empty".into(),
            ));
        }

        let versioned_ids: Vec<String> = user_ids
            .iter()
            .map(|id| {
                if id.contains('_') {
                    id.clone()
                } else {
                    format!("{id}_0")
                }
            })
            .collect();

        let base = format!(
            "{}/api/social/friend/getprofiles/v2",
            self.session.core.services.profile_base()
        );
        let url = self
            .session
            .core
            .gateway
            .build_endpoint_url(&base, &[], true)?;
        let params = json!({
            "phonebook_version": self.session.core.extra_ver.phonebook,
            "friend_pversion_map": versioned_ids,
            "avatar_size": avatar as u16,
            "language": self.session.core.language,
            "show_online_status": 1,
            "imei": self.session.core.imei,
        });

        self.session
            .core
            .gateway
            .post_encrypted_form(url, &self.session.core.cipher, &params, false)
            .await
    }

    /// Lists friends of the logged-in account with pagination.
    pub async fn list_friends(
        &self,
        page: u32,
        count: u32,
        avatar: AvatarPreset,
    ) -> ZaloxResult<Value> {
        let base = format!(
            "{}/api/social/friend/getfriends",
            self.session.core.services.profile_base()
        );
        let url = self
            .session
            .core
            .gateway
            .build_endpoint_url(&base, &[], true)?;
        let params = json!({
            "incInvalid": 1,
            "page": page.max(1),
            "count": count.max(1),
            "avatar_size": avatar as u16,
            "actiontime": 0,
            "imei": self.session.core.imei,
        });

        self.session
            .core
            .gateway
            .request_encrypted_query(
                Method::GET,
                url,
                &self.session.core.cipher,
                &params,
                true,
                false,
            )
            .await
    }

    /// Sends a friend request with a custom greeting message.
    pub async fn send_friend_request(
        &self,
        target_uid: &str,
        greeting: &str,
    ) -> ZaloxResult<Value> {
        let base = format!(
            "{}/api/friend/sendreq",
            self.session.core.services.friend_base()
        );
        let url = self
            .session
            .core
            .gateway
            .build_endpoint_url(&base, &[], true)?;
        let params = json!({
            "toid": target_uid,
            "msg": greeting,
            "reqsrc": 30,
            "imei": self.session.core.imei,
            "language": self.session.core.language,
        });

        self.session
            .core
            .gateway
            .post_encrypted_form(url, &self.session.core.cipher, &params, true)
            .await
    }

    /// Accepts an incoming friend request from `requester_uid`.
    pub async fn accept_friend_request(&self, requester_uid: &str) -> ZaloxResult<Value> {
        let base = format!(
            "{}/api/friend/accept",
            self.session.core.services.friend_base()
        );
        let url = self
            .session
            .core
            .gateway
            .build_endpoint_url(&base, &[], true)?;
        let params = json!({
            "fid": requester_uid,
            "language": self.session.core.language,
        });

        self.session
            .core
            .gateway
            .post_encrypted_form(url, &self.session.core.cipher, &params, true)
            .await
    }

    /// Rejects an incoming friend request from `requester_uid`.
    pub async fn reject_friend_request(&self, requester_uid: &str) -> ZaloxResult<Value> {
        let base = format!(
            "{}/api/friend/reject",
            self.session.core.services.friend_base()
        );
        let url = self
            .session
            .core
            .gateway
            .build_endpoint_url(&base, &[], true)?;
        let params = json!({ "fid": requester_uid });

        self.session
            .core
            .gateway
            .post_encrypted_form(url, &self.session.core.cipher, &params, true)
            .await
    }

    /// Updates the custom nickname (alias) displayed for a friend.
    pub async fn set_alias(&self, friend_uid: &str, alias: &str) -> ZaloxResult<Value> {
        let alias_base = self.session.core.services.endpoint_or(
            &self.session.core.services.alias,
            self.session.core.services.friend_base(),
        );
        let base = format!("{alias_base}/api/alias/update");
        let url = self
            .session
            .core
            .gateway
            .build_endpoint_url(&base, &[], true)?;
        let params = json!({
            "friendId": friend_uid,
            "alias": alias,
            "imei": self.session.core.imei,
        });

        self.session
            .core
            .gateway
            .request_encrypted_query(
                Method::GET,
                url,
                &self.session.core.cipher,
                &params,
                true,
                true,
            )
            .await
    }
}
