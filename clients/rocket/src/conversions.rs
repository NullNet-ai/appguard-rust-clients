use nullnet_libappguard::appguard::{
    AppGuardHttpRequest, AppGuardHttpResponse, AppGuardTcpConnection, AppGuardTcpInfo,
};
use qstring::QString;
use rocket::http::HeaderMap;
use rocket::{Request, Response};
use std::collections::HashMap;
use std::net::SocketAddr;

pub(crate) fn to_appguard_tcp_connection(req: &Request, token: String) -> AppGuardTcpConnection {
    let source_ip = req.client_ip().map(|ip| ip.to_string());
    let source_port = req.remote().map(|s| u32::from(s.port()));

    let destination: Option<SocketAddr> = None;

    let protocol = String::new();

    AppGuardTcpConnection {
        token,
        source_ip,
        source_port,
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

    let query: HashMap<String, String> = if let Some(q) = req.uri().query() {
        QString::from(q.to_string().as_str()).into_iter().collect()
    } else {
        HashMap::new()
    };

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

pub(crate) fn to_appguard_http_response(
    res: &Response,
    tcp_info: Option<AppGuardTcpInfo>,
    token: String,
) -> AppGuardHttpResponse {
    let headers = convert_headers(res.headers());

    AppGuardHttpResponse {
        token,
        code: u32::from(res.status().code),
        headers,
        tcp_info,
    }
}

fn convert_headers(headers: &HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .map(|h| (h.name().to_string(), h.value.to_string()))
        .collect()
}
