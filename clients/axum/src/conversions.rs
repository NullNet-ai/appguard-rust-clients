use axum::extract::Request;
use axum::http::{HeaderMap, Response};
use qstring::QString;
use std::collections::HashMap;
use std::net::SocketAddr;

use nullnet_libappguard::{
    AppGuardHttpRequest, AppGuardHttpResponse, AppGuardTcpConnection, AppGuardTcpInfo,
};

pub(crate) fn to_appguard_tcp_connection(req: &Request, token: String) -> AppGuardTcpConnection {
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

fn convert_headers(headers: &HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect()
}
