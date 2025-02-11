use twitter_v2::TwitterApi;
use twitter_v2::authorization::{Oauth2Token, BearerToken};
use twitter_v2::query::{TweetField, UserField};
use time::{OffsetDateTime, Duration};
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore = "must set APP_BEARER_TOKEN"]
	#[tokio::test]
    async fn test_get_user_tweets() {
        let auth = BearerToken::new(std::env::var("APP_BEARER_TOKEN").unwrap());
        let cli = TwitterApi::new(auth);
        // let user = cli.get_user_by_username("realDonaldTrump").send().await.unwrap().into_data().unwrap().id;
        let user = cli.get_user_by_username("VitalikButerin").send().await.unwrap().into_data().unwrap();
        // let user_id = user.data.id
        println!("user: {:?}", user.id);
        println!("");

        // let user_id = user.data.id;
        let ten_minutes_ago = OffsetDateTime::now_utc() - Duration::hours(10);

        let tweet = cli.get_user_tweets(user.id).start_time(ten_minutes_ago).send().await.unwrap().into_data().unwrap();
        println!("tweet: {:?}", tweet);
    }
}