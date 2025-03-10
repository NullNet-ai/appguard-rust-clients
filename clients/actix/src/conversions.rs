use std::collections::HashMap;

use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::header::HeaderMap;
use nullnet_libappguard::{
    AppGuardHttpRequest, AppGuardHttpResponse, AppGuardTcpConnection, AppGuardTcpInfo,
    Authentication,
};
use qstring::QString;

pub(crate) fn to_appguard_tcp_connection(
    req: &ServiceRequest,
    token: String,
) -> AppGuardTcpConnection {
    let source_ip = req
        .connection_info()
        .realip_remote_addr()
        .map(std::string::ToString::to_string);
    let source_port = req.peer_addr().map(|s| u32::from(s.port()));
    let destination = req.app_config().local_addr();
    AppGuardTcpConnection {
        auth: Some(Authentication { token }),
        source_ip,
        source_port,
        destination_ip: Some(destination.ip().to_string()),
        destination_port: Some(u32::from(destination.port())),
        protocol: req.connection_info().scheme().to_string(),
    }
}

pub(crate) fn to_appguard_http_request(
    req: &ServiceRequest,
    tcp_info: Option<AppGuardTcpInfo>,
    token: String,
) -> AppGuardHttpRequest {
    let headers = convert_headers(req.headers());

    let query: HashMap<String, String> = QString::from(req.query_string()).into_iter().collect();

    AppGuardHttpRequest {
        auth: Some(Authentication { token }),
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
    token: String,
) -> AppGuardHttpResponse {
    let headers = convert_headers(res.headers());

    AppGuardHttpResponse {
        auth: Some(Authentication { token }),
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
