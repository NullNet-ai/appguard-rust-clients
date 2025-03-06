use axum::extract::Request;
use axum::http::{HeaderMap, Response};
use qstring::QString;
use std::collections::HashMap;
use std::net::SocketAddr;

use nullnet_libappguard::{AppGuardHttpRequest, AppGuardHttpResponse, AppGuardTcpConnection, AppGuardTcpInfo, Authentication};

pub(crate) fn to_appguard_tcp_connection(req: &Request) -> AppGuardTcpConnection {
    let source = req
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|c| c.0);

    let destination: Option<SocketAddr> = None;

    let protocol = req
        .extensions()
        .get::<axum_extra::extract::Scheme>()
        .map(|s| s.0.clone())
        .unwrap_or_default();

    AppGuardTcpConnection {
        auth: Authentication { token: "".to_string() },
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
) -> AppGuardHttpRequest {
    let headers = convert_headers(req.headers());

    let query: HashMap<String, String> = QString::from(req.uri().query().unwrap_or_default())
        .into_iter()
        .collect();

    AppGuardHttpRequest {
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
) -> AppGuardHttpResponse {
    let headers = convert_headers(res.headers());

    AppGuardHttpResponse {
        code: u32::from(res.status().as_u16()),
        headers,
        tcp_info,
    }
}

fn convert_headers(headers: &HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect()
}
