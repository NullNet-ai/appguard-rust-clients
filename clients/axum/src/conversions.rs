use appguard_client_authentication::CacheKey;
use axum::extract::Request;
use axum::http::{HeaderMap, Response};
use nullnet_libappguard::appguard::{
    AppGuardHttpRequest, AppGuardHttpResponse, AppGuardTcpConnection, AppGuardTcpInfo,
};
use qstring::QString;
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;

pub(crate) fn to_appguard_tcp_connection(req: &Request, token: String) -> AppGuardTcpConnection {
    let source = get_source_socket(req);

    let destination: Option<SocketAddr> = None;

    let protocol = req
        .extensions()
        .get::<axum_extra::extract::Scheme>()
        .map(|s| s.0.clone())
        .unwrap_or_default();

    AppGuardTcpConnection {
        token,
        source_ip: source.map(|s| s.ip().to_string()),
        source_port: source.map(|s| u32::from(s.port())),
        destination_ip: destination.map(|s| s.ip().to_string()),
        destination_port: destination.map(|s| u32::from(s.port())),
        protocol,
    }
}

pub(crate) fn to_appguard_http_request(
    req: &Request,
    tcp_info: Option<AppGuardTcpInfo>,
    token: String,
) -> AppGuardHttpRequest {
    let headers = convert_headers(req.headers());

    let query: HashMap<String, String> = QString::from(req.uri().query().unwrap_or_default())
        .into_iter()
        .collect();

    AppGuardHttpRequest {
        token,
        original_url: req.uri().path().to_string(),
        headers,
        method: req.method().to_string(),
        body: None,
        query,
        tcp_info,
    }
}

pub(crate) fn to_appguard_http_response<B>(
    res: &Response<B>,
    tcp_info: Option<AppGuardTcpInfo>,
    token: String,
) -> AppGuardHttpResponse {
    let headers = convert_headers(res.headers());

    AppGuardHttpResponse {
        token,
        code: u32::from(res.status().as_u16()),
        headers,
        tcp_info,
    }
}

pub(crate) fn to_cache_key(req: &Request) -> CacheKey {
    let headers = convert_headers(req.headers());
    let query: BTreeMap<String, String> = QString::from(req.uri().query().unwrap_or_default())
        .into_iter()
        .collect();
    let source_ip = get_source_socket(req).map(|s| s.ip().to_string());
    let user_agent = headers
        .get("user-agent")
        .unwrap_or(&String::new())
        .to_string();

    CacheKey {
        original_url: req.uri().path().to_string(),
        user_agent,
        method: req.method().to_string(),
        body: String::new(),
        query,
        source_ip: source_ip.unwrap_or_default(),
    }
}

fn convert_headers(headers: &HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .map(|(k, v)| {
            (
                k.to_string().to_ascii_lowercase(),
                v.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

fn get_source_socket(req: &Request) -> Option<SocketAddr> {
    req.extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|c| c.0)
}
