use strum::Display;

#[derive(Copy, Clone, Debug, Display)]
#[strum(serialize_all = "snake_case")]
pub enum TweetExpansion {
    AuthorId,
    #[strum(serialize = "referenced_tweets.id")]
    ReferencedTweetsId,
    InReplyToUserId,
    #[strum(serialize = "attachments.media_keys")]
    AttachmentsMediaKeys,
    #[strum(serialize = "attachments.poll_ids")]
    AttachmentsPollIds,
    #[strum(serialize = "geo.place_id")]
    GeoPlaceId,
    #[strum(serialize = "entities.mentions.username")]
    EntitiesMentionsUsername,
    #[strum(serialize = "referenced_tweets.id.author_id")]
    ReferencedTweetsIdAuthorId,
}

#[derive(Copy, Clone, Debug, Display)]
#[strum(serialize_all = "snake_case")]
pub enum UserExpansion {
    PinnedTweetId,
}

#[derive(Copy, Clone, Debug, Display)]
#[strum(serialize_all = "snake_case")]
pub enum SpaceExpansion {
    InvitedUserIds,
    SpeakerIds,
    CreatorId,
    HostIds,
}

#[derive(Copy, Clone, Debug, Display)]
#[strum(serialize_all = "snake_case")]
pub enum LimitedTweetExpansion {
    AuthorId,
}

#[derive(Copy, Clone, Debug, Display)]
#[strum(serialize_all = "snake_case")]
pub enum ListExpansion {
    OwnerId,
}
