use log::{debug, info};
use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use warp::http::{HeaderMap, StatusCode, Uri};
use warp::{Filter, Rejection, Reply};


static WEB_AAD_LOGOUT: &str =
    "https://login.microsoftonline.com/common/oauth2/v2.0/logout?post_logout_redirect_uri=";

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Configuration {
    tenant_id:String,
    default_page: String,
    redirect_uri: String,
    client_id: String,
    client_secret: String,
}

impl Configuration {
    fn new(
        tenant_id:String,
        default_page: String,
        redirect_uri: String,
        client_id: String,
        client_secret: String,
    ) -> Self {
        Configuration {
            tenant_id,
            default_page,
            redirect_uri,
            client_id,
            client_secret,
        }
    }
}

#[derive(Clone)]
struct Store {
    grocery_list: Arc<RwLock<Configuration>>,
}

impl Store {
    fn new(
        tenant_id: String,
        default_page: String,
        redirect_uri: String,
        client_id: String,
        client_secret: String,
    ) -> Self {
        Store {
            grocery_list: Arc::new(RwLock::new(Configuration::new(
                tenant_id,
                default_page,
                redirect_uri,
                client_id,
                client_secret,
            ))),
        }
    }
}
async fn get_logout(
    params: HashMap<String, String>,
    headers: HeaderMap,
    store: Store,
) -> Result<impl Reply, Rejection> {
    debug!(
        "Logout Page , Header > {:#?} \r\n Query string > {:#?}",
        headers, params
    );
    let conf = store.grocery_list.read().await;
    let sign_out_url = format!("{}{}", WEB_AAD_LOGOUT, urlencoding::encode(conf.clone().default_page.as_str()));
    debug!("redirect to url > {}", sign_out_url);
    let result = Uri::from_str(sign_out_url.as_str());
    Ok(warp::redirect(result.unwrap()))
}
async fn get_callback(
    params: HashMap<String, String>,
    headers: HeaderMap,
    store: Store,
) -> Result<impl Reply, Rejection> {
    debug!(
        "Callback Page , Header > {:#?} \r\n Query string > {:#?}",
        headers, params
    );

    Ok(warp::reply::with_status("", StatusCode::OK))
}
async fn index(headers: HeaderMap, store: Store) -> Result<impl Reply, Rejection> {
    debug!("Index Page , Header > {:#?}", headers);
    let conf = store.grocery_list.read().await;
    let client =
        BasicClient::new(
            ClientId::new(conf.clone().client_id),
            Some(ClientSecret::new(conf.clone().client_secret)),
            AuthUrl::new(
                format!("https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",conf.clone().tenant_id).to_string()
            ).unwrap(),
            None
        )
            // Set the URL the user will be redirected to after the authorization process.
            .set_redirect_uri(RedirectUrl::new(conf.clone().redirect_uri).unwrap());

    let (pkce_challenge, _pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        // Set the desired scopes.
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("User.Read".to_string()))
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .add_extra_param("response_mode", "form_post")
        //.add_extra_param("state","redir=./questions")
        .url();

    let auth_url = format!("{}", auth_url);
    debug!("Url : {}", auth_url.clone());

    let result = Uri::from_str(auth_url.as_str());
    Ok(warp::redirect(result.unwrap()))
}
#[tokio::main]
async fn main() {
    pretty_env_logger::init();
    info!("Web example 003 starting..");

    let store = Store::new(
        env::var("TENANT_ID").unwrap(),
        env::var("DEFAULT_PAGE").unwrap(),
        env::var("REDIRECT_URL").unwrap(),
        env::var("CLIENT_ID").unwrap(),
        env::var("CLIENT_SECRET").unwrap(),
    );

    info!("Load environment variable complete");

    let store_filter = warp::any().map(move || store.clone());

    let index_page = warp::path::end()
        .and(warp::header::headers_cloned())
        .and(store_filter.clone())
        .and_then(index);
    let callback_page = warp::path::path("callback")
        .and(warp::query::query::<HashMap<String, String>>())
        .and(warp::path::end())
        .and(warp::header::headers_cloned())
        .and(store_filter.clone())
        .and_then(get_callback);
    let logout_page = warp::path::path("logout")
        .and(warp::query::query::<HashMap<String, String>>())
        .and(warp::path::end())
        .and(warp::header::headers_cloned())
        .and(store_filter.clone())
        .and_then(get_logout);

    let routes = index_page.or(callback_page).or(logout_page);
    warp::serve(routes).run(([0, 0, 0, 0], 8080)).await;
}
