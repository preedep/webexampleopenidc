use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation, decode_header};
use log::{debug, error, info};
use oauth2::basic::{BasicClient};
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, ResponseType, Scope, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::Read;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use warp::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use warp::reject::Reject;
use warp::{Filter, Rejection, Reply};
use warp_sessions::{MemoryStore, SessionWithStore};

static WEB_AAD_URL: &str = "https://login.microsoftonline.com/";

static WEB_AAD_AUTH: &str = "/oauth2/v2.0/authorize";
static WEB_AAD_TOKEN: &str = "/oauth2/v2.0/token";
static WEB_AAD_LOGOUT: &str = "/oauth2/v2.0/logout";

static SESSION_KEY_ACCESS_TOKEN: &str = "access_token";
static SESSION_STATE: &str = "state";

#[derive(Debug)]
struct CallbackInvalid;
impl Reject for CallbackInvalid {}

#[derive(Debug)]
struct AccessTokenInvalid;
impl Reject for AccessTokenInvalid {}

///
///     JWT Payload
///
///
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JwtPayload {
    pub aud: String,
    pub iss: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    pub acct: i64,
    pub acr: String,
    pub aio: String,
    pub altsecid: String,
    pub amr: Vec<String>,
    #[serde(rename = "app_displayname")]
    pub app_displayname: String,
    pub appid: String,
    pub appidacr: String,
    pub email: String,
    #[serde(rename = "family_name")]
    pub family_name: String,
    #[serde(rename = "given_name")]
    pub given_name: String,
    pub idp: String,
    pub idtyp: String,
    pub ipaddr: String,
    pub name: String,
    pub oid: String,
    pub platf: String,
    pub puid: String,
    pub rh: String,
    pub scp: String,
    pub sub: String,
    #[serde(rename = "tenant_region_scope")]
    pub tenant_region_scope: String,
    pub tid: String,
    #[serde(rename = "unique_name")]
    pub unique_name: String,
    pub uti: String,
    pub ver: String,
    pub wids: Vec<String>,
    #[serde(rename = "xms_st")]
    pub xms_st: XmsSt,
    #[serde(rename = "xms_tcdt")]
    pub xms_tcdt: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct XmsSt {
    pub sub: String,
}

///
/// JWT Payload for ID Token
///

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JwtPayloadIDToken {
    pub aud: Option<String>,
    pub iss: Option<String>,
    pub iat: Option<i64>,
    pub nbf: Option<i64>,
    pub exp: Option<i64>,
    pub acct: Option<i64>,
    pub acrs: Option<Vec<String>>,
    pub aio: Option<String>,
    #[serde(rename = "auth_time")]
    pub auth_time: Option<i64>,
    pub ctry: Option<String>,
    pub email: Option<String>,
    #[serde(rename = "family_name")]
    pub family_name: Option<String>,
    #[serde(rename = "given_name")]
    pub given_name: Option<String>,
    pub idp: Option<String>,
    pub ipaddr: Option<String>,
    #[serde(rename = "login_hint")]
    pub login_hint: Option<String>,
    pub name: Option<String>,
    pub nonce: Option<String>,
    pub oid: Option<String>,
    #[serde(rename = "preferred_username")]
    pub preferred_username: Option<String>,
    pub rh: Option<String>,
    pub sid: Option<String>,
    pub sub: Option<String>,
    #[serde(rename = "tenant_ctry")]
    pub tenant_ctry: Option<String>,
    #[serde(rename = "tenant_region_scope")]
    pub tenant_region_scope: Option<String>,
    pub tid: Option<String>,
    pub uti: Option<String>,
    pub ver: Option<String>,
    #[serde(rename = "xms_pl")]
    pub xms_pl: Option<String>,
    #[serde(rename = "xms_tpl")]
    pub xms_tpl: Option<String>,
    pub department: Option<String>,
    pub companyname: Option<String>,
}


///
/// Open ID Configuration
///
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenIDConfigurationV2 {
    #[serde(rename = "token_endpoint")]
    pub token_endpoint: String,
    #[serde(rename = "token_endpoint_auth_methods_supported")]
    pub token_endpoint_auth_methods_supported: Vec<String>,
    #[serde(rename = "jwks_uri")]
    pub jwks_uri: String,
    #[serde(rename = "response_modes_supported")]
    pub response_modes_supported: Vec<String>,
    #[serde(rename = "subject_types_supported")]
    pub subject_types_supported: Vec<String>,
    #[serde(rename = "id_token_signing_alg_values_supported")]
    pub id_token_signing_alg_values_supported: Vec<String>,
    #[serde(rename = "response_types_supported")]
    pub response_types_supported: Vec<String>,
    #[serde(rename = "scopes_supported")]
    pub scopes_supported: Vec<String>,
    pub issuer: String,
    #[serde(rename = "request_uri_parameter_supported")]
    pub request_uri_parameter_supported: bool,
    #[serde(rename = "userinfo_endpoint")]
    pub userinfo_endpoint: String,
    #[serde(rename = "authorization_endpoint")]
    pub authorization_endpoint: String,
    #[serde(rename = "device_authorization_endpoint")]
    pub device_authorization_endpoint: String,
    #[serde(rename = "http_logout_supported")]
    pub http_logout_supported: bool,
    #[serde(rename = "frontchannel_logout_supported")]
    pub frontchannel_logout_supported: bool,
    #[serde(rename = "end_session_endpoint")]
    pub end_session_endpoint: String,
    #[serde(rename = "claims_supported")]
    pub claims_supported: Vec<String>,
    #[serde(rename = "kerberos_endpoint")]
    pub kerberos_endpoint: String,
    #[serde(rename = "tenant_region_scope")]
    pub tenant_region_scope: String,
    #[serde(rename = "cloud_instance_name")]
    pub cloud_instance_name: String,
    #[serde(rename = "cloud_graph_host_name")]
    pub cloud_graph_host_name: String,
    #[serde(rename = "msgraph_host")]
    pub msgraph_host: String,
    #[serde(rename = "rbac_url")]
    pub rbac_url: String,
}

///
///    JWKSUrlInf
///
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JWKS {
    pub keys: Vec<Key>,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Key {
    pub kty: String,
    #[serde(rename = "use")]
    pub use_field: String,
    pub kid: String,
    pub x5t: String,
    pub n: String,
    pub e: String,
    pub x5c: Vec<String>,
}

///
///   Configuration object
///
///
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

//
// Store warp state
//
//
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
//
// create azure ad url
//
fn get_aad_url(aad_host: String, ten_nant_id: String, oauth2_path: String) -> String {
    let url = format!("{}{}{}", aad_host, ten_nant_id, oauth2_path);
    info!("Called aad url > {}", url.to_owned());
    url
}
//
//  no cache
//
fn disable_cache(reply: impl Reply) -> impl Reply {
    warp::reply::with_header(reply, "cache_control", HeaderValue::from_static("no-cache"))
}
//
//  get_logout
//
async fn get_logout(
    params: HashMap<String, String>,
    session_with_store: SessionWithStore<MemoryStore>,
    headers: HeaderMap,
    store: Store,
) -> Result<impl Reply, Rejection> {
    debug!(
        "Logout Page , Header > {:#?} \r\n Query string > {:#?}",
        headers, params
    );
    if !session_with_store.to_owned().session.is_destroyed() {
        info!("destroy session ");
        session_with_store.to_owned().session.destroy();
    }

    let conf = store.grocery_list.read().await;
    let aad_logout = get_aad_url(
        WEB_AAD_URL.to_string(),
        conf.to_owned().tenant_id,
        WEB_AAD_LOGOUT.to_string(),
    );

    let sign_out_url = format!(
        "{}?post_logout_redirect_uri={}",
        aad_logout,
        urlencoding::encode(conf.clone().default_page.as_str())
    );
    debug!("redirect to url > {}", sign_out_url);
    let result = Uri::from_str(sign_out_url.as_str());
    Ok(warp::redirect(result.unwrap()))
}
//
//  get_profile
//
//
async fn get_profile(
    query: HashMap<String, String>,
    session_with_store: SessionWithStore<MemoryStore>,
    headers: HeaderMap,
    store: Store,
) -> Result<impl Reply, Rejection> {
    debug!("\r\n=====\r\nProfile Page , Header > {:#?} \r\n", headers,);
    debug!("Session > {:#?}", session_with_store.session);
    let mut text_display = String::new();
    let conf = store.grocery_list.read().await;
    let token = session_with_store
        .session
        .get::<String>(SESSION_KEY_ACCESS_TOKEN);
    match token {
        None => {
            debug!("no access token");
            Err(warp::reject::custom(AccessTokenInvalid))
        }
        Some(t) => {
            let access_token = t;
            debug!("have access token : {}", access_token);
            let response_type = query.get("response_type");
            if let Some(res) = response_type {
                if res.eq("code") {
                    // code
                    let key = DecodingKey::from_secret(&[]);
                    let mut validation = Validation::new(Algorithm::HS256);
                    validation.insecure_disable_signature_validation();
                    let data = decode::<JwtPayload>(access_token.as_str(), &key, &validation);
                    match data {
                        Ok(payload) => {
                            info!("jwt : {:#?}", &payload);
                            let url_openid_config =
                                format!("https://login.microsoftonline.com/{}/v2.0/.well-known/openid-configuration?appid={}",
                                        payload.to_owned().claims.tid,
                                        payload.to_owned().claims.appid);
                            info!("url validation : {}", url_openid_config);
                            let t = reqwest::get(url_openid_config)
                                .await
                                .unwrap()
                                .json::<OpenIDConfigurationV2>()
                                .await;
                            match t {
                                Ok(o) => {
                                    debug!("Open ID Configuration : {:#?}", o);
                                    // verify issuer
                                    if o.to_owned()
                                        .issuer
                                        .as_str()
                                        .contains(conf.to_owned().tenant_id.as_str())
                                    {
                                        info!("Issuer is collect");
                                        info!("Issuer from OpenID Configuration {} ,\r\n Issuer from JWT Payload {}"
                                            ,o.to_owned()
                                            .issuer,payload.to_owned().claims.iss
                                        );
                                        let jwks = reqwest::get(o.to_owned().jwks_uri)
                                            .await
                                            .unwrap()
                                            .json::<JWKS>()
                                            .await;
                                        match jwks {
                                            Ok(j) => {
                                                debug!("JWKS : {:#?}", j);
                                            }
                                            Err(e) => {
                                                error!("Get JWKS URL error : {}", e);
                                            }
                                        }
                                        let client = reqwest::Client::new();
                                        let res_user_info = client
                                            .get(o.to_owned().userinfo_endpoint)
                                            .header(
                                                "Authorization",
                                                format!("Bearer {}", access_token),
                                            )
                                            .send()
                                            .await;
                                        match res_user_info {
                                            Ok(r) => {
                                                debug!("Get user info : {:#?}", r);
                                            }
                                            Err(e) => {
                                                error!("Get user info err : {}", e);
                                            }
                                        }
                                    } else {
                                        error!("Issuer is not collect");
                                    }
                                }
                                Err(e) => {
                                    error!("Get open id config error {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Decode without validation  > {}", e);
                        }
                    }
                } else {
                    // ID Token
                    let header = decode_header(&access_token.as_str()).unwrap();
                    debug!("JWT Header : \r\n{:#?}", header);

                    let state = session_with_store
                        .session
                        .get::<String>(SESSION_STATE).unwrap_or("".to_string());
                    debug!("State : {}",state);

                    let pem_bytes = include_bytes!("key.pem");
                    debug!("\r\n{}", String::from_utf8_lossy(pem_bytes));
                    let key = DecodingKey::from_rsa_pem(pem_bytes);
                    let validation = Validation::new(Algorithm::RS256);
                    let data = decode::<JwtPayloadIDToken>(access_token.as_str(),
                                                           &key.unwrap(),
                                                           &validation);
                    match data {
                        Ok(payload) => {
                            text_display.push_str(
                                format!(r#"Name : {}-{}
                                <br/>
                                Department : {}
                                <br/>
                                Company : {}
                                <br/>
                                "#,
                                payload.claims.given_name.unwrap_or("".to_string()),
                                payload.claims.family_name.unwrap_or("".to_string()),
                                payload.claims.department.unwrap_or("".to_string()),
                                payload.claims.companyname.unwrap_or("".to_string())).as_str()
                            );
                        }
                        Err(e) => {
                            error!("Decode validation  > {}", e);
                        }
                    }
                }
            }
            let body = format!(r#"
    <body>
    <h1>
    Welcome <br/> {}
    </h1>
    <br/>
    <br/>
     <a href="/logout">Logout</a>
    </body>
    "#,text_display);

            Ok(warp::reply::html(body))
        }
    }
}

//
//  callback
//  for response_type = token_id (openidc)
//
async fn post_callback_token_id(
    forms: HashMap<String, String>,
    mut session_with_store: SessionWithStore<MemoryStore>,
    headers: HeaderMap,
    _store: Store,
) -> Result<impl Reply, Rejection> {
    debug!("\r\n======\r\nCallback page , Header > {:#?}", headers);
    debug!("Form value : {:#?}", forms);

    return match forms.get("id_token") {
        None => Err(warp::reject::custom(AccessTokenInvalid)),
        Some(token) => {
            let result = Uri::from_str("/profile?response_type=id_token");
            // save access token to session
            let shared_session = Arc::new(RwLock::new(session_with_store.session));
            let _res = shared_session
                .write()
                .await
                .insert(SESSION_KEY_ACCESS_TOKEN, token)
                .unwrap();

            let _res = shared_session.write()
                .await.insert(SESSION_STATE,forms.get("state")).unwrap();


            session_with_store.session = Arc::try_unwrap(shared_session).unwrap().into_inner();
            debug!("Session > {:#?}", session_with_store.session);

            //redirect
            let res = warp_sessions::reply::with_session(
                warp::redirect::redirect(result.unwrap()),
                session_with_store,
            )
            .await;
            Ok(res.unwrap())
        }
    };
    //Ok(warp::reply::with_status("",StatusCode::OK))
}

//
//  get_callback
//
//
async fn get_callback(
    params: HashMap<String, String>,
    mut session_with_store: SessionWithStore<MemoryStore>,
    headers: HeaderMap,
    store: Store,
) -> Result<impl Reply, Rejection> {
    debug!(
        "\r\n=======\r\nCallback Page , Header > {:#?} \r\n \
        Query string > {:#?}",
        headers,
        params
    );
    debug!("Session > {:#?}",
        session_with_store.to_owned().session);


    match params.get("code") {
        None => Err(warp::reject::custom(CallbackInvalid)),
        Some(c) => {
            info!("get auth code complete");
            let conf = store.grocery_list.read().await;
            let client = BasicClient::new(
                ClientId::new(conf.clone().client_id),
                Some(ClientSecret::new(conf.clone().client_secret)),
                AuthUrl::new(get_aad_url(
                    WEB_AAD_URL.to_string(),
                    conf.to_owned().tenant_id,
                    WEB_AAD_AUTH.to_string(),
                ))
                .unwrap(),
                Some(
                    TokenUrl::new(get_aad_url(
                        WEB_AAD_URL.to_string(),
                        conf.to_owned().tenant_id,
                        WEB_AAD_TOKEN.to_string(),
                    ))
                    .unwrap(),
                ),
            )
            //.set_auth_type(AuthType::RequestBody)
            .set_redirect_uri(RedirectUrl::new(conf.clone().redirect_uri).unwrap());

            /*
            let verifier = store.pkce_table.read().await;
            let verifier = verifier.get(params.get("state").unwrap());
            */
            let shared_session = Arc::new(RwLock::new(session_with_store.to_owned().session));
            let verifier = shared_session
                .read()
                .await
                .get::<PkceCodeVerifier>(params.get("state").unwrap());

            return match verifier {
                None => Err(warp::reject::custom(CallbackInvalid)),
                Some(v) => {
                    let token_result = client
                        .exchange_code(AuthorizationCode::new(c.to_string()))
                        .add_extra_param("code_verifier", v.secret())
                        .request_async(async_http_client)
                        .await;

                    match token_result {
                        Ok(t) => {
                            info!("Basic Token Response : {:#?}", t);
                            info!("Access token : {}", t.access_token().secret());
                            let result = Uri::from_str("/profile?response_type=code");
                            // save access token to session
                            let shared_session = Arc::new(RwLock::new(session_with_store.to_owned().session));
                            let _res = shared_session
                                .write()
                                .await
                                .insert(SESSION_KEY_ACCESS_TOKEN, t.access_token().secret())
                                .unwrap();

                            session_with_store.session =
                                Arc::try_unwrap(shared_session).unwrap().into_inner();
                            //redirect
                            let res = warp_sessions::reply::with_session(
                                warp::redirect::redirect(result.unwrap()),
                                session_with_store,
                            )
                            .await;
                            Ok(res.unwrap())
                        }
                        Err(e) => {
                            error!("Error {:#?}", e);
                            Err(warp::reject::custom(CallbackInvalid))
                        }
                    }
                }
            };
        }
    }
}

//
//  login page
//  for response_type = code
//
async fn get_login(
    query: HashMap<String, String>,
    mut session_with_store: SessionWithStore<MemoryStore>,
    headers: HeaderMap,
    store: Store,
) -> Result<impl Reply, Rejection> {
    debug!("\r\n=====\r\nLogin page , Header > {:#?}", headers);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    debug!("PKCE challenge : {:?} \r\n ,\
            PKCE verifier {:?}", pkce_challenge, pkce_verifier);

    let conf = store.grocery_list.read().await;
    let client = BasicClient::new(
        ClientId::new(conf.clone().client_id),
        Some(ClientSecret::new(conf.to_owned().client_secret)),
        AuthUrl::new(get_aad_url(
            WEB_AAD_URL.to_string(),
            conf.to_owned().tenant_id,
            WEB_AAD_AUTH.to_string(),
        ))
        .unwrap(),
        None,
    )
    // Set the URL the user will be redirected to after the authorization process.
    .set_redirect_uri(RedirectUrl::new(conf.clone().redirect_uri).unwrap());
    //response-type = id_token is openid scenario

    // Generate the full authorization URL.
    let mut auth_req = client
        .authorize_url(CsrfToken::new_random)
        // Set the desired scopes.
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("User.Read".to_string()))
        .set_pkce_challenge(pkce_challenge);

    let mut response_type = ResponseType::new("code".to_string());
    let mut response_mode = "query";
    if let Some(t) = query.get("response_type") {
        response_type = ResponseType::new(t.to_string());
        if t.eq("id_token") {
            response_mode = "form_post";
            auth_req = auth_req.add_extra_param("nonce", "1234234233232322222")
        }
    }
    auth_req = auth_req.add_extra_param("response_mode", response_mode);
    auth_req = auth_req.set_response_type(&response_type);
    let (auth_url, csrf_token) = auth_req.url();

    debug!("csrf_token = {}", csrf_token.secret());
    /*
    store
        .pkce_table
        .write()
        .await
        .insert(csrf_token.secret().to_string(), pkce_verifier);
*/
    let shared_session = Arc::new(RwLock::new(session_with_store.clone().session));
    let _res = shared_session
        .write()
        .await
        .insert(csrf_token.secret().as_str(), pkce_verifier)
        .unwrap();

    let auth_url = format!("{}", auth_url);
    debug!("Url : {}", auth_url.clone());

    debug!("Session value at login page > {:#?}",session_with_store.to_owned().session);

    let result = Uri::from_str(auth_url.as_str());
    let reply = warp_sessions::reply::with_session(
        warp::redirect(result.unwrap()),
        session_with_store).await;
    //Ok(disable_cache(reply))
    Ok(reply.unwrap())
}
//
//  return_error
//
//
async fn return_error(r: Rejection) -> Result<impl Reply, Rejection> {
    error!("Call return_error : {:#?}", r);
    if let Some(_callback_invalid) = r.find::<CallbackInvalid>() {
        Ok(warp::reply::with_status(
            "UNAUTHORIZED",
            StatusCode::UNAUTHORIZED,
        ))
    } else if let Some(_token_invalid) = r.find::<AccessTokenInvalid>() {
        Ok(warp::reply::with_status(
            "UNAUTHORIZED",
            StatusCode::UNAUTHORIZED,
        ))
    } else {
        Ok(warp::reply::with_status(
            "Route not found",
            StatusCode::NOT_FOUND,
        ))
    }
}
//
//  index , main page
//
//
async fn index(headers: HeaderMap, _store: Store) -> Result<impl Reply, Rejection> {
    debug!("Index Page , Header > {:#?}", headers);
    let body = r#"
        <html>
            <body>
                <a href="/login?response_type=code">Login with Azure AD (Auth Code )</a><br/>
                  <a href="/login?response_type=id_token">Login with Azure AD (ID Token - OpenIDC)</a><br/>
                <a href="/logout">Logout</a>
            </body>
    </html>
    "#;
    let reply = warp::reply::html(body);
    Ok(disable_cache(reply))
}


//
//  main
//
//
#[tokio::main]
async fn main() {
    pretty_env_logger::init();
    info!("Web example 003 starting..");

    let session_store = MemoryStore::new();
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

    let login_page = warp::get()
        .and(warp::path::path("login"))
        .and(warp::query::query::<HashMap<String, String>>())
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and(warp::path::end())
        .and(warp::header::headers_cloned())
        .and(store_filter.clone())
        .and_then(get_login);

    let post_token_id_callback_page = warp::post()
        .and(warp::path::path("callback"))
        .and(warp::body::form::<HashMap<String, String>>())
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and(warp::path::end())
        .and(warp::header::headers_cloned())
        .and(store_filter.clone())
        .and_then(post_callback_token_id);

    let callback_page = warp::get() //warp::path::path("callback")
        .and(warp::path::path("callback"))
        .and(warp::query::query::<HashMap<String, String>>())
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and(warp::path::end())
        .and(warp::header::headers_cloned())
        .and(store_filter.clone())
        .and_then(get_callback);

    //.and(get_callback)

    let profile_page = warp::get()
        .and(warp::path::path("profile"))
        .and(warp::query::query::<HashMap<String, String>>())
        .and(warp::path::end())
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and(warp::header::headers_cloned())
        .and(store_filter.clone())
        .and_then(get_profile);

    let logout_page = warp::get()
        .and(warp::path::path("logout"))
        .and(warp::query::query::<HashMap<String, String>>())
        .and(warp_sessions::request::with_session(
            session_store.clone(),
            None,
        ))
        .and(warp::path::end())
        .and(warp::header::headers_cloned())
        .and(store_filter.clone())
        .and_then(get_logout);

    let log = warp::log("webexample003");

    let routes = index_page
        .or(login_page)
        .or(post_token_id_callback_page)
        .or(callback_page)
        .or(profile_page)
        .or(logout_page)
        .with(log)
        .recover(return_error);
    warp::serve(routes).run(([0, 0, 0, 0], 8080)).await;
}
