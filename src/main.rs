use log::{debug, error, info};
use oauth2::basic::{BasicClient, BasicTokenResponse};
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use warp::http::{header, HeaderMap, StatusCode, Uri};
use warp::{Filter, Rejection, Reply};
use warp::reject::Reject;

static WEB_AAD_LOGOUT: &str =
    "https://login.microsoftonline.com/common/oauth2/v2.0/logout?post_logout_redirect_uri=";


#[derive(Debug)]
struct CallbackInvalid;
impl Reject for CallbackInvalid {}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Configuration {
    tenant_id: String,
    default_page: String,
    redirect_uri: String,
    client_id: String,
    client_secret: String,
}

impl Configuration {
    fn new(
        tenant_id: String,
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
    pkce_table: Arc<RwLock<HashMap<String, PkceCodeVerifier>>>,
}

impl Store {
    fn new(
        tenant_id: String,
        default_page: String,
        redirect_uri: String,
        client_id: String,
        client_secret: String,
    ) -> Self {
        let table: HashMap<String, PkceCodeVerifier> = HashMap::new();
        Store {
            grocery_list: Arc::new(RwLock::new(Configuration::new(
                tenant_id,
                default_page,
                redirect_uri,
                client_id,
                client_secret,
            ))),
            pkce_table: Arc::new(RwLock::new(table)),
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
    let sign_out_url = format!(
        "{}{}",
        WEB_AAD_LOGOUT,
        urlencoding::encode(conf.clone().default_page.as_str())
    );
    debug!("redirect to url > {}", sign_out_url);
    let result = Uri::from_str(sign_out_url.as_str());
    Ok(warp::redirect(result.unwrap()))
}
async fn get_profile(headers: HeaderMap, store: Store) -> Result<impl Reply, Rejection> {
    debug!("Profile Page , Header > {:#?} \r\n", headers,);

    let body = r#"
    <body>
    <h1>
    Welcome
    </h1>
    </body>
    ""#;
    Ok(warp::reply::html(body))
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
    match params.get("code") {
        None => {}
        Some(c) => {
            let conf = store.grocery_list.read().await;

            let client = BasicClient::new(
                ClientId::new(conf.clone().client_id),
                Some(ClientSecret::new(conf.clone().client_secret)),
                AuthUrl::new(
                    format!(
                        "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
                        conf.clone().tenant_id
                    )
                    .to_string(),
                )
                .unwrap(),
                Some(
                    TokenUrl::new(
                        format!(
                            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                            conf.clone().tenant_id
                        )
                        .to_string(),
                    )
                    .unwrap(),
                ),
            )
            .set_auth_type(AuthType::RequestBody)
            .set_redirect_uri(RedirectUrl::new(conf.clone().redirect_uri).unwrap());

            //let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
            let verifier = store.pkce_table.read().await;

            let verifier = verifier.get(params.get("state").unwrap());
            match verifier {
                None => {}
                Some(v) => {
                    let token_result = client
                        .exchange_code(AuthorizationCode::new(c.to_string()))
                        //.set_pkce_verifier(*v)
                        .add_extra_param("code_verifier", v.secret())
                        .request_async(async_http_client)
                        .await;

                    match token_result {
                        Ok(t) => {
                            info!("Basic Token Response : {:#?}", t);
                            info!("Access token : {}", t.access_token().secret());
                            let result = Uri::from_str("/profile");
                            /*
                            redirect
                            */
                            //headers.insert("ACCESS_TOKEN", t.access_token().secret().parse()?);
                            return Ok(warp::redirect::redirect(result.unwrap()));

                        }
                        Err(e) => {
                            error!("Error {:#?}", e);
                        }
                    }
                }
            }
        }
    }
    Err(warp::reject::custom(CallbackInvalid))
}
async fn index(headers: HeaderMap, store: Store) -> Result<impl Reply, Rejection> {
    debug!("Index Page , Header > {:#?}", headers);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    debug!("PKCE : {:?},{:?}", pkce_challenge, pkce_verifier);

    let conf = store.grocery_list.read().await;
    let client = BasicClient::new(
        ClientId::new(conf.clone().client_id),
        Some(ClientSecret::new(conf.clone().client_secret)),
        AuthUrl::new(
            format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
                conf.clone().tenant_id
            )
            .to_string(),
        )
        .unwrap(),
        None,
    )
    // Set the URL the user will be redirected to after the authorization process.
    .set_redirect_uri(RedirectUrl::new(conf.clone().redirect_uri).unwrap());

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
        .add_extra_param("response_mode", "query")
        //.add_extra_param("state","redir=./questions")
        .url();

    debug!("csrf_token = {}", csrf_token.secret());
    store
        .pkce_table
        .write()
        .await
        .insert(csrf_token.secret().to_string(), pkce_verifier);

    let auth_url = format!("{}", auth_url);
    debug!("Url : {}", auth_url.clone());

    let result = Uri::from_str(auth_url.as_str());
    Ok(warp::redirect(result.unwrap()))
    //Ok(warp::reply::with_status("",StatusCode::OK))
}

async fn return_error(r: Rejection) -> Result<impl Reply, Rejection> {
    error!("Call return_error : {:#?}", r);

    if let Some(_callback_invalid) = r.find::<CallbackInvalid>() {
        Ok(warp::reply::with_status(
            "UNAUTHORIZED",
            StatusCode::UNAUTHORIZED,
        ))
    } else{
        Ok(warp::reply::with_status(
            "Route not found",
            StatusCode::NOT_FOUND,
        ))
    }
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
    let profile_page = warp::path::path("profile")
        .and(warp::path::end())
        .and(warp::header::headers_cloned())
        .and(store_filter.clone())
        .and_then(get_profile);
    let logout_page = warp::path::path("logout")
        .and(warp::query::query::<HashMap<String, String>>())
        .and(warp::path::end())
        .and(warp::header::headers_cloned())
        .and(store_filter.clone())
        .and_then(get_logout);

    let routes = index_page
        .or(callback_page)
        .or(profile_page)
        .or(logout_page).recover(return_error);
    warp::serve(routes).run(([0, 0, 0, 0], 8080)).await;
}
