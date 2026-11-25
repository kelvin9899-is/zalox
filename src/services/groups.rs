//! Group discovery, metadata inspection, group creation, member management,
//! and interactive group polls.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    error::{ZaloxError, ZaloxResult},
    session::{now_epoch_ms, ZaloxSession},
};

/// Configuration for creating a group poll.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollBlueprint {
    pub question: String,
    pub options: Vec<String>,
    pub expired_time_ms: u64,
    pub allow_multi_choices: bool,
    pub allow_add_new_option: bool,
    pub hide_vote_preview: bool,
    pub is_anonymous: bool,
}

impl PollBlueprint {
    pub fn new(question: impl Into<String>, options: Vec<String>) -> Self {
        Self {
            question: question.into(),
            options,
            expired_time_ms: 0,
            allow_multi_choices: false,
            allow_add_new_option: false,
            hide_vote_preview: false,
            is_anonymous: false,
        }
    }
}

/// Domain facade for managing Zalo groups and polls.
#[derive(Clone)]
pub struct GroupsService {
    session: ZaloxSession,
}

impl GroupsService {
    pub(crate) fn new(session: ZaloxSession) -> Self {
        Self { session }
    }

    /// Lists all group IDs and sync versions the current account belongs to (`getlg/v4`).
    pub async fn list_joined_groups(&self) -> ZaloxResult<Value> {
        let base = format!(
            "{}/api/group/getlg/v4",
            self.session.core.services.group_poll_base()
        );
        let url = self
            .session
            .core
            .gateway
            .build_endpoint_url(&base, &[], true)?;
        self.session
            .core
            .gateway
            .get_encrypted_response(url, &self.session.core.cipher)
            .await
    }

    /// Fetches rich metadata, settings, and member lists for one or more groups (`getmg-v2`).
    pub async fn fetch_groups(&self, group_ids: &[String]) -> ZaloxResult<Value> {
        if group_ids.is_empty() {
            return Err(ZaloxError::InvalidInput(
                "group_ids must not be empty".into(),
            ));
        }

        let ver_map: HashMap<&str, u8> = group_ids.iter().map(|id| (id.as_str(), 0u8)).collect();
        let base = format!(
            "{}/api/group/getmg-v2",
            self.session.core.services.group_base()
        );
        let url = self
            .session
            .core
            .gateway
            .build_endpoint_url(&base, &[], true)?;
        let params = json!({
            "gridVerMap": serde_json::to_string(&ver_map)?,
        });

        self.session
            .core
            .gateway
            .post_encrypted_form(url, &self.session.core.cipher, &params, false)
            .await
    }

    /// Creates a new group with an optional title and initial member UIDs.
    pub async fn create_group(
        &self,
        name: Option<&str>,
        member_uids: &[String],
    ) -> ZaloxResult<Value> {
        if member_uids.is_empty() {
            return Err(ZaloxError::InvalidInput(
                "Creating a group requires at least one member UID".into(),
            ));
        }

        let now = now_epoch_ms();
        let (gname, name_changed) = match name.filter(|s| !s.trim().is_empty()) {
            Some(n) => (n.to_owned(), 1),
            None => (now.to_string(), 0),
        };
        let member_types: Vec<i8> = vec![-1; member_uids.len()];

        let base = format!(
            "{}/api/group/create/v2",
            self.session.core.services.group_base()
        );
        let url = self
            .session
            .core
            .gateway
            .build_endpoint_url(&base, &[], true)?;
        let params = json!({
            "clientId": now,
            "gname": gname,
            "gdesc": Value::Null,
            "members": member_uids,
            "membersTypes": member_types,
            "nameChanged": name_changed,
            "createLink": 1,
            "clientLang": self.session.core.language,
            "imei": self.session.core.imei,
            "zsource": 601,
        });

        self.session
            .core
            .gateway
            .request_encrypted_query(
                reqwest::Method::POST,
                url,
                &self.session.core.cipher,
                &params,
                true,
                true,
            )
            .await
    }

    /// Renames an existing group.
    pub async fn rename_group(&self, group_id: &str, new_name: &str) -> ZaloxResult<Value> {
        let base = format!(
            "{}/api/group/updateinfo",
            self.session.core.services.group_base()
        );
        let url = self
            .session
            .core
            .gateway
            .build_endpoint_url(&base, &[], true)?;
        let params = json!({
            "grid": group_id,
            "gname": new_name,
        });

        self.session
            .core
            .gateway
            .post_encrypted_form(url, &self.session.core.cipher, &params, true)
            .await
    }

    /// Invites/adds members into an existing group.
    pub async fn add_members(&self, group_id: &str, member_uids: &[String]) -> ZaloxResult<Value> {
        let base = format!(
            "{}/api/group/invite/v2",
            self.session.core.services.group_base()
        );
        let url = self
            .session
            .core
            .gateway
            .build_endpoint_url(&base, &[], true)?;
        let member_types: Vec<i8> = vec![-1; member_uids.len()];
        let params = json!({
            "grid": group_id,
            "members": member_uids,
            "memberTypes": member_types,
            "rf": 1,
            "clientLang": self.session.core.language,
        });

        self.session
            .core
            .gateway
            .post_encrypted_form(url, &self.session.core.cipher, &params, true)
            .await
    }

    /// Removes (kicks) members from a group where the current account is owner/deputy.
    pub async fn remove_members(
        &self,
        group_id: &str,
        member_uids: &[String],
    ) -> ZaloxResult<Value> {
        let base = format!(
            "{}/api/group/kickout",
            self.session.core.services.group_base()
        );
        let url = self
            .session
            .core
            .gateway
            .build_endpoint_url(&base, &[], true)?;
        let params = json!({
            "grid": group_id,
            "members": member_uids,
        });

        self.session
            .core
            .gateway
            .post_encrypted_form(url, &self.session.core.cipher, &params, true)
            .await
    }

    /// Leaves a group (`silent = true` suppresses leave notification if supported).
    pub async fn leave_group(&self, group_id: &str, silent: bool) -> ZaloxResult<Value> {
        let base = format!(
            "{}/api/group/leave",
            self.session.core.services.group_base()
        );
        let url = self
            .session
            .core
            .gateway
            .build_endpoint_url(&base, &[], true)?;
        let params = json!({
            "grids": [group_id],
            "imei": self.session.core.imei,
            "silent": u8::from(silent),
            "language": self.session.core.language,
        });

        self.session
            .core
            .gateway
            .post_encrypted_form(url, &self.session.core.cipher, &params, true)
            .await
    }

    /// Creates a new poll inside `group_id`.
    pub async fn create_poll(&self, group_id: &str, poll: PollBlueprint) -> ZaloxResult<Value> {
        if poll.question.trim().is_empty() || poll.options.len() < 2 {
            return Err(ZaloxError::InvalidInput(
                "Group poll requires a non-empty question and at least 2 options".into(),
            ));
        }

        let base = format!(
            "{}/api/poll/create",
            self.session.core.services.group_base()
        );
        let url = self
            .session
            .core
            .gateway
            .build_endpoint_url(&base, &[], true)?;
        let params = json!({
            "group_id": group_id,
            "question": poll.question,
            "options": poll.options,
            "expired_time": poll.expired_time_ms,
            "pinAct": false,
            "allow_multi_choices": poll.allow_multi_choices,
            "allow_add_new_option": poll.allow_add_new_option,
            "is_hide_vote_preview": poll.hide_vote_preview,
            "is_anonymous": poll.is_anonymous,
            "poll_type": 0,
            "src": 1,
            "imei": self.session.core.imei,
        });

        self.session
            .core
            .gateway
            .post_encrypted_form(url, &self.session.core.cipher, &params, true)
            .await
    }
}
