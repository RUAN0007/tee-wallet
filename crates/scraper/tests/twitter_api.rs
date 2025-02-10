use twitter_v2::TwitterApi;
use twitter_v2::authorization::{Oauth2Token, BearerToken};
use twitter_v2::query::{TweetField, UserField};
use time::{OffsetDateTime, Duration};

#[cfg(test)]
mod tests {
    use super::*;

	#[tokio::test]
    async fn test_get_user_id() {
        let auth = BearerToken::new(std::env::var("APP_BEARER_TOKEN").unwrap());
        let cli = TwitterApi::new(auth);
        let user = cli.get_user_by_username("realDonaldTrump").send().await.unwrap();
        // let user_id = user.data.id
        println!("user: {:?}", user);
        let user_id = 0 as u64;
        // let user_id = user.data.id;
        let ten_minutes_ago = OffsetDateTime::now_utc() - Duration::minutes(10);
        let tweet = cli.get_user_tweets(user_id).start_time(ten_minutes_ago).send().await.unwrap();
        println!("tweet: {:?}", tweet);
    }
}