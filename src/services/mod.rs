//! Domain-scoped service facades (`messaging`, `contacts`, `groups`, `media`).

pub mod contacts;
pub mod groups;
pub mod image_probe;
pub mod media;
pub mod messaging;

pub use contacts::ContactsService;
pub use groups::{GroupsService, PollBlueprint};
pub use image_probe::{probe_image_dimensions, ImageFormatKind, ImageGeometry};
pub use media::{MediaService, MediaSource, UploadedAttachment};
pub use messaging::{
    MentionSpan, MessageDraft, MessageReceipt, MessageUrgency, MessagingService, ReactionKind,
    SpanStyle, TextDecoration,
};
