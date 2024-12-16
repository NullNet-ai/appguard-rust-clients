use std::collections::HashMap;

use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::header::HeaderMap;
use appguard_clients_common::{
    AppGuardHttpRequest, AppGuardHttpResponse, AppGuardTcpConnection, AppGuardTcpInfo,
};
use qstring::QString;

pub(crate) fn to_appguard_tcp_connection(req: &ServiceRequest) -> AppGuardTcpConnection {
    let source = req.peer_addr();
    let destination = req.app_config().local_addr();
    AppGuardTcpConnection {
        source_ip: source.map(|s| s.ip().to_string()),
        source_port: source.map(|s| u32::from(s.port())),
        destination_ip: Some(destination.ip().to_string()),
        destination_port: Some(u32::from(destination.port())),
        protocol: req.connection_info().scheme().to_string(),
    }
}

pub(crate) fn to_appguard_http_request(
    req: &ServiceRequest,
    tcp_info: Option<AppGuardTcpInfo>,
) -> AppGuardHttpRequest {
    let headers = convert_headers(req.headers());

    let query: HashMap<String, String> = QString::from(req.query_string()).into_iter().collect();

    AppGuardHttpRequest {
        original_url: req.path().to_string(),
        headers,
        method: req.method().to_string(),
        body: None,
        query,
        tcp_info,
    }
}

pub(crate) fn to_appguard_http_response<B>(
    res: &ServiceResponse<B>,
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
