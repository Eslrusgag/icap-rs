use crate::error::IcapResult;
use crate::http::{HttpMessage, HttpMessageTrait};
use crate::request::Request;
use crate::response::Response;
use std::collections::HashMap;
use std::str::FromStr;

/// Разделяет строку заголовка на имя и значение
#[inline]
pub fn split_header(line: &str) -> Option<(String, String)> {
    line.find(':').map(|pos| {
        (
            line[..pos].trim().to_string(),
            line[pos + 1..].trim().to_string(),
        )
    })
}

/// Проверяет, является ли строка началом HTTP сообщения
#[inline]
pub fn is_http_start_line(line: &str) -> bool {
    line.starts_with("HTTP/")
        || line.starts_with("GET ")
        || line.starts_with("POST ")
        || line.starts_with("PUT ")
        || line.starts_with("DELETE ")
        || line.starts_with("HEAD ")
        || line.starts_with("OPTIONS ")
        || line.starts_with("PATCH ")
}

/// Парсит ICAP запрос из сырых байтов
pub fn parse_icap_request(data: &[u8]) -> IcapResult<Request> {
    let text = String::from_utf8_lossy(data);
    let mut lines = text.lines();

    // Разбор первой строки
    let request_line = lines.next().ok_or("Empty request")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("Invalid request line")?.to_string();
    let uri = parts.next().ok_or("Invalid request line")?.to_string();
    let version = parts.next().ok_or("Invalid request line")?.to_string();

    let mut request = Request::new(&method, &uri, &version);

    // Временные структуры для HTTP сообщений
    let mut current_http: Option<HttpMessage> = None;
    let mut in_icap_headers = true;

    for line in lines {
        let line = line.trim();

        if line.is_empty() {
            if in_icap_headers {
                in_icap_headers = false;
                continue;
            } else if let Some(msg) = current_http.take() {
                // Заканчиваем HTTP сообщение
                if method == "REQMOD" {
                    request.http_request = Some(msg);
                } else if method == "RESPMOD" {
                    request.http_response = Some(msg);
                }
                continue;
            }
        }

        if in_icap_headers {
            if is_http_start_line(line) {
                // Начало HTTP сообщения
                current_http = Some(HttpMessage {
                    start_line: line.to_string(),
                    headers: HashMap::new(),
                    body: Vec::new(),
                });
                in_icap_headers = false;
            } else if let Some((name, value)) = split_header(line) {
                request.headers.insert(name, value);
            }
        } else if let Some(http_msg) = current_http.as_mut() {
            if let Some((name, value)) = split_header(line) {
                http_msg.headers.insert(name, value);
            } else {
                http_msg.body.extend_from_slice(line.as_bytes());
                http_msg.body.extend_from_slice(b"\r\n");
            }
        }
    }

    if let Some(msg) = current_http {
        if method == "REQMOD" {
            request.http_request = Some(msg);
        } else if method == "RESPMOD" {
            request.http_response = Some(msg);
        }
    }

    Ok(request)
}

/// Сериализует ICAP запрос в байты
pub fn serialize_icap_request(request: &Request) -> Vec<u8> {
    let mut raw = Vec::new();

    // Request line
    raw.extend_from_slice(
        format!("{} {} {}\r\n", request.method, request.uri, request.version).as_bytes(),
    );

    // Headers
    for (name, value) in &request.headers {
        raw.extend_from_slice(format!("{}: {}\r\n", name, value).as_bytes());
    }

    // Empty line
    raw.extend_from_slice(b"\r\n");

    // HTTP message if present
    if let Some(ref http_req) = request.http_request {
        raw.extend_from_slice(&http_req.to_raw());
    }

    if let Some(ref http_resp) = request.http_response {
        raw.extend_from_slice(&http_resp.to_raw());
    }

    raw
}

/// Сериализует ICAP ответ в байты
pub fn serialize_icap_response(response: &Response) -> IcapResult<Vec<u8>> {
    let mut result = Vec::new();

    // Status line
    let status_line = format!(
        "{} {} {}\r\n",
        response.version, response.status_code, response.status_text
    );
    result.extend_from_slice(status_line.as_bytes());

    // Headers
    for (name, value) in &response.headers {
        let header_line = format!("{}: {}\r\n", name, value);
        result.extend_from_slice(header_line.as_bytes());
    }

    // Empty line
    result.extend_from_slice(b"\r\n");

    // Body
    if !response.body.is_empty() {
        result.extend_from_slice(&response.body);
    }

    Ok(result)
}

/// Проверяет, является ли ICAP запрос полным
pub fn is_complete_icap_request(buffer: &[u8]) -> bool {
    let content = String::from_utf8_lossy(buffer);
    let lines: Vec<&str> = content.lines().collect();

    // Ищем двойной перенос строки, который разделяет заголовки и тело
    let mut empty_line_count = 0;
    let line_count = lines.len();

    for line in &lines {
        if line.trim().is_empty() {
            empty_line_count += 1;
            if empty_line_count >= 2 {
                return true;
            }
        }
    }

    // Если нет двойного переноса, проверяем, есть ли хотя бы заголовки
    line_count >= 2
}

/// Проверяет, является ли ICAP ответ полным
pub fn is_complete_icap_response(buffer: &[u8]) -> bool {
    let content = String::from_utf8_lossy(buffer);
    let lines: Vec<&str> = content.lines().collect();

    // Look for double newline that separates headers and body
    let mut empty_line_count = 0;

    for line in &lines {
        if line.trim().is_empty() {
            empty_line_count += 1;
            if empty_line_count >= 2 {
                return true;
            }
        }
    }

    // If no double newline, check if we have at least headers
    lines.len() >= 2
}

/// Извлекает имя сервиса из URI
pub fn extract_service_name(uri: &str) -> IcapResult<String> {
    // URI формат: icap://host:port/service
    if let Some(service_start) = uri.rfind('/') {
        Ok(uri[service_start + 1..].to_string())
    } else {
        Err("Invalid ICAP URI format".into())
    }
}

/// Парсит ICAP ответ из сырых байтов
pub fn parse_icap_response(raw: &[u8]) -> IcapResult<Response> {
    if raw.is_empty() {
        return Err("Empty response".into());
    }

    let content = String::from_utf8_lossy(raw);
    let mut lines = content.lines();

    // Parse status line
    let status_line = lines.next().ok_or("Empty response")?;
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() < 3 {
        return Err("Invalid status line format".into());
    }

    let version = parts[0].to_string();
    let status_code = match crate::response::StatusCode::from_str(parts[1]) {
        Ok(code) => code,
        Err(_) => {
            // Try to parse as unknown status code
            if let Ok(code_num) = parts[1].parse::<u16>() {
                // Create a custom status code for unknown values
                match code_num {
                    100 => crate::response::StatusCode::Continue100,
                    200 => crate::response::StatusCode::Ok200,
                    204 => crate::response::StatusCode::NoContent204,
                    400 => crate::response::StatusCode::BadRequest400,
                    404 => crate::response::StatusCode::NotFound404,
                    405 => crate::response::StatusCode::MethodNotAllowed405,
                    413 => crate::response::StatusCode::RequestEntityTooLarge413,
                    500 => crate::response::StatusCode::InternalServerError500,
                    503 => crate::response::StatusCode::ServiceUnavailable503,
                    504 => crate::response::StatusCode::GatewayTimeout504,
                    _ => return Err(format!("Unknown ICAP status code: {}", code_num).into()),
                }
            } else {
                return Err("Invalid status code format".into());
            }
        }
    };
    let status_text = parts[2..].join(" ");

    let mut headers = HashMap::new();
    let mut body_start = 0;

    // Parse headers
    for (line_num, line) in lines.enumerate() {
        if line.is_empty() {
            body_start = line_num + 1;
            break;
        }

        if let Some(colon_pos) = line.find(':') {
            let name = line[..colon_pos].trim();
            let value = line[colon_pos + 1..].trim();
            if !name.is_empty() {
                headers.insert(name.to_string(), value.to_string());
            }
        }
    }

    // Extract body
    let body = if body_start > 0 {
        let body_lines: Vec<&str> = content.lines().skip(body_start).collect();
        body_lines.join("\n").into_bytes()
    } else {
        Vec::new()
    };

    Ok(Response {
        version,
        status_code,
        status_text,
        headers,
        body,
    })
}
