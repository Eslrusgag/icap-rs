use icap_rs::{
    HttpMessage, HttpMessageTrait, IcapMethod, IcapOptionsBuilder, Request, Response, Server,
    StatusCode, TransferBehavior, error::IcapError,
};
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Инициализируем логирование
    tracing_subscriber::fmt::init();

    // Создаем OPTIONS конфигурацию для сервиса request-modifier
    let request_modifier_options =
        IcapOptionsBuilder::new(vec![IcapMethod::ReqMod], "request-modifier-v1.0")
            .service("ICAP Request Modifier Service 1.0")
            .max_connections(500)
            .options_ttl(3600)
            .with_current_date()
            .service_id("req-modifier")
            .allow_204()
            .preview(1024)
            .transfer_rule("exe", TransferBehavior::Complete)
            .transfer_rule("zip", TransferBehavior::Complete)
            .default_transfer_behavior(TransferBehavior::Preview)
            .custom_header("X-Modifier-Version", "1.0.0")
            .custom_header("X-Security-Policy", "Strict")
            .build()?;

    // Создаем OPTIONS конфигурацию для сервиса response-modifier
    let response_modifier_options =
        IcapOptionsBuilder::new(vec![IcapMethod::RespMod], "response-modifier-v1.0")
            .service("ICAP Response Modifier Service 1.0")
            .max_connections(500)
            .options_ttl(3600)
            .with_current_date()
            .service_id("resp-modifier")
            .allow_204()
            .preview(2048)
            .transfer_rule("html", TransferBehavior::Preview)
            .transfer_rule("js", TransferBehavior::Complete)
            .default_transfer_behavior(TransferBehavior::Preview)
            .custom_header("X-Content-Filter", "Active")
            .build()?;

    // Создаем сервер с модификаторами
    let server = Server::builder()
        .bind("127.0.0.1:1344")
        .add_service("request-modifier", request_modifier_handler)
        .add_options_config("request-modifier", request_modifier_options)
        .add_service("response-modifier", response_modifier_handler)
        .add_options_config("response-modifier", response_modifier_options)
        .build()
        .await?;

    info!("ICAP Request/Response Modifier Server started on 127.0.0.1:1344");
    info!("Available services:");
    info!("  - icap://127.0.0.1:1344/request-modifier (REQMOD)");
    info!("    * Blocks malicious URLs");
    info!("    * Adds security headers");
    info!("    * Modifies user agents");
    info!("  - icap://127.0.0.1:1344/response-modifier (RESPMOD)");
    info!("    * Filters HTML content");
    info!("    * Adds security headers to responses");
    info!("    * Blocks dangerous file types");
    info!("");
    info!("Test URLs:");
    info!("  Normal:     http://example.com/page");
    info!("  Malicious:  http://malware-site.com/virus.exe");
    info!("  Blocked:    http://gambling-site.com/casino");

    // Запускаем сервер
    server.run().await.map_err(|e| e.into())
}

/// Обработчик для модификации HTTP запросов (REQMOD)
async fn request_modifier_handler(request: Request) -> Result<Response, IcapError> {
    info!("Request modifier processing: {}", request.method);

    match request.method.as_str() {
        "REQMOD" => {
            if let Some(http_request) = request.http_request {
                info!("Processing HTTP request: {}", http_request.start_line);

                // Анализируем запрос
                let analysis = analyze_request(&http_request);

                match analysis.action {
                    RequestAction::Block(reason) => {
                        warn!("Blocking request: {}", reason);

                        // Создаем 403 Forbidden ответ
                        let block_response = create_403_response(&reason);

                        return Ok(Response::new(StatusCode::Ok200, "OK")
                            .add_header("ISTag", "\"request-modifier-v1.0\"")
                            .add_header("Encapsulated", "res-hdr=0, res-body=200")
                            .with_body(&block_response));
                    }
                    RequestAction::Modify => {
                        info!("Modifying request");

                        // Модифицируем запрос
                        let modified_request = modify_request(http_request);

                        return Ok(Response::new(StatusCode::Ok200, "OK")
                            .add_header("ISTag", "\"request-modifier-v1.0\"")
                            .add_header("Encapsulated", "req-hdr=0, req-body=300")
                            .with_body(&modified_request.to_raw()));
                    }
                    RequestAction::Allow => {
                        info!("Request allowed without modification");

                        // Пропускаем без изменений
                        return Ok(Response::new(StatusCode::NoContent204, "No Content")
                            .add_header("ISTag", "\"request-modifier-v1.0\""));
                    }
                }
            }

            // Если нет HTTP запроса, возвращаем ошибку
            Ok(Response::new(StatusCode::BadRequest400, "Bad Request")
                .add_header("ISTag", "\"request-modifier-v1.0\""))
        }
        _ => Ok(Response::new(
            StatusCode::MethodNotAllowed405,
            "Method Not Allowed",
        )),
    }
}

/// Обработчик для модификации HTTP ответов (RESPMOD)
async fn response_modifier_handler(request: Request) -> Result<Response, IcapError> {
    info!("Response modifier processing: {}", request.method);

    match request.method.as_str() {
        "RESPMOD" => {
            if let Some(http_response) = request.http_response {
                info!("Processing HTTP response: {}", http_response.start_line);

                // Анализируем ответ
                let analysis = analyze_response(&http_response);

                match analysis.action {
                    ResponseAction::Block(reason) => {
                        warn!("Blocking response: {}", reason);

                        // Создаем блокирующий ответ
                        let block_response = create_blocked_content_response(&reason);

                        return Ok(Response::new(StatusCode::Ok200, "OK")
                            .add_header("ISTag", "\"response-modifier-v1.0\"")
                            .add_header("Encapsulated", "res-hdr=0, res-body=250")
                            .with_body(&block_response));
                    }
                    ResponseAction::Modify => {
                        info!("Modifying response");

                        // Модифицируем ответ
                        let modified_response = modify_response(http_response);

                        return Ok(Response::new(StatusCode::Ok200, "OK")
                            .add_header("ISTag", "\"response-modifier-v1.0\"")
                            .add_header("Encapsulated", "res-hdr=0, res-body=400")
                            .with_body(&modified_response.to_raw()));
                    }
                    ResponseAction::Allow => {
                        info!("Response allowed without modification");

                        return Ok(Response::new(StatusCode::NoContent204, "No Content")
                            .add_header("ISTag", "\"response-modifier-v1.0\""));
                    }
                }
            }

            Ok(Response::new(StatusCode::BadRequest400, "Bad Request")
                .add_header("ISTag", "\"response-modifier-v1.0\""))
        }
        _ => Ok(Response::new(
            StatusCode::MethodNotAllowed405,
            "Method Not Allowed",
        )),
    }
}

#[derive(Debug)]
enum RequestAction {
    Allow,
    Modify,
    Block(String),
}

#[derive(Debug)]
enum ResponseAction {
    Allow,
    Modify,
    Block(String),
}

#[derive(Debug)]
struct RequestAnalysis {
    action: RequestAction,
}

#[derive(Debug)]
struct ResponseAnalysis {
    action: ResponseAction,
}

/// Анализирует HTTP запрос и определяет необходимое действие
fn analyze_request(http_request: &HttpMessage) -> RequestAnalysis {
    let url = &http_request.start_line;

    // Проверяем на вредоносные URL
    if url.contains("malware") || url.contains("virus") || url.contains("trojan") {
        return RequestAnalysis {
            action: RequestAction::Block("Malicious URL detected".to_string()),
        };
    }

    // Проверяем на заблокированные категории
    if url.contains("gambling") || url.contains("casino") || url.contains("porn") {
        return RequestAnalysis {
            action: RequestAction::Block("Blocked category".to_string()),
        };
    }

    // Проверяем на подозрительные расширения
    if url.contains(".exe") || url.contains(".bat") || url.contains(".scr") {
        return RequestAnalysis {
            action: RequestAction::Block("Dangerous file type".to_string()),
        };
    }

    // Проверяем User-Agent
    if let Some(user_agent) = http_request.get_header("User-Agent") {
        if user_agent.contains("bot") || user_agent.contains("crawler") {
            return RequestAnalysis {
                action: RequestAction::Modify,
            };
        }
    }

    // Проверяем на отсутствие важных заголовков
    if !http_request.has_header("Host") {
        return RequestAnalysis {
            action: RequestAction::Modify,
        };
    }

    RequestAnalysis {
        action: RequestAction::Allow,
    }
}

/// Анализирует HTTP ответ и определяет необходимое действие
fn analyze_response(http_response: &HttpMessage) -> ResponseAnalysis {
    // Проверяем Content-Type
    if let Some(content_type) = http_response.get_header("Content-Type") {
        // Блокируем исполняемые файлы
        if content_type.contains("application/octet-stream")
            || content_type.contains("application/x-executable")
            || content_type.contains("application/x-msdownload")
        {
            return ResponseAnalysis {
                action: ResponseAction::Block("Executable file blocked".to_string()),
            };
        }

        // Модифицируем HTML контент
        if content_type.contains("text/html") {
            return ResponseAnalysis {
                action: ResponseAction::Modify,
            };
        }

        // Модифицируем JavaScript
        if content_type.contains("application/javascript")
            || content_type.contains("text/javascript")
        {
            return ResponseAnalysis {
                action: ResponseAction::Modify,
            };
        }
    }

    // Проверяем размер ответа
    if http_response.body.len() > 50 * 1024 * 1024 {
        // 50MB
        return ResponseAnalysis {
            action: ResponseAction::Block("File too large".to_string()),
        };
    }

    // Проверяем содержимое на вредоносные паттерны
    let body_text = String::from_utf8_lossy(&http_response.body);
    if body_text.contains("<script>alert('xss')</script>")
        || body_text.contains("eval(")
        || body_text.contains("document.write(")
    {
        return ResponseAnalysis {
            action: ResponseAction::Block("Malicious script detected".to_string()),
        };
    }

    ResponseAnalysis {
        action: ResponseAction::Allow,
    }
}

/// Модифицирует HTTP запрос
fn modify_request(mut http_request: HttpMessage) -> HttpMessage {
    info!("Applying request modifications");

    // Добавляем/модифицируем User-Agent если это бот
    if let Some(user_agent) = http_request.get_header("User-Agent") {
        if user_agent.contains("bot") || user_agent.contains("crawler") {
            http_request.headers.insert(
                "User-Agent".to_string(),
                "Mozilla/5.0 (Filtered-Bot) ICAP-Modified/1.0".to_string(),
            );
            info!("Modified User-Agent for bot");
        }
    }

    // Добавляем заголовки безопасности
    http_request.headers.insert(
        "X-ICAP-Modified".to_string(),
        "request-modifier-v1.0".to_string(),
    );

    http_request
        .headers
        .insert("X-Security-Policy".to_string(), "strict".to_string());

    // Добавляем Host если отсутствует
    if !http_request.has_header("Host") {
        http_request
            .headers
            .insert("Host".to_string(), "default.example.com".to_string());
        info!("Added missing Host header");
    }

    info!("Request modification completed");
    http_request
}

/// Модифицирует HTTP ответ
fn modify_response(mut http_response: HttpMessage) -> HttpMessage {
    info!("Applying response modifications");

    // Добавляем заголовки безопасности
    http_response
        .headers
        .insert("X-Content-Type-Options".to_string(), "nosniff".to_string());

    http_response
        .headers
        .insert("X-Frame-Options".to_string(), "DENY".to_string());

    http_response
        .headers
        .insert("X-XSS-Protection".to_string(), "1; mode=block".to_string());

    http_response.headers.insert(
        "Strict-Transport-Security".to_string(),
        "max-age=31536000; includeSubDomains".to_string(),
    );

    http_response.headers.insert(
        "X-ICAP-Modified".to_string(),
        "response-modifier-v1.0".to_string(),
    );

    // Модифицируем контент в зависимости от типа
    let content_type = http_response.get_header("Content-Type").cloned();

    if let Some(ct) = content_type {
        if ct.contains("text/html") {
            let mut body_text = String::from_utf8_lossy(&http_response.body).to_string();

            // Удаляем потенциально опасные скрипты
            body_text = body_text.replace("eval(", "/* blocked eval */ (");
            body_text = body_text.replace("document.write(", "/* blocked document.write */ (");

            // Добавляем CSP meta-тег если это HTML
            if body_text.contains("<head>") {
                body_text = body_text.replace(
                    "<head>",
                    "<head>\n<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';\">",
                );
                info!("Added CSP meta tag");
            }

            // Добавляем информацию о модификации
            if body_text.contains("</body>") {
                body_text = body_text.replace(
                    "</body>",
                    "<!-- Content filtered by ICAP Response Modifier v1.0 -->\n</body>",
                );
            }

            http_response.body = body_text.into_bytes();

            // Обновляем Content-Length
            http_response.headers.insert(
                "Content-Length".to_string(),
                http_response.body.len().to_string(),
            );

            info!("HTML content modification completed");
        } else if ct.contains("javascript") {
            let mut js_content = String::from_utf8_lossy(&http_response.body).to_string();

            // Блокируем опасные функции
            js_content = js_content.replace("eval(", "/* BLOCKED eval */ (");
            js_content = js_content.replace("Function(", "/* BLOCKED Function */ (");

            // Добавляем комментарий о модификации
            js_content = format!(
                "/* Modified by ICAP Response Modifier v1.0 */\n{}",
                js_content
            );

            http_response.body = js_content.into_bytes();
            http_response.headers.insert(
                "Content-Length".to_string(),
                http_response.body.len().to_string(),
            );

            info!("JavaScript content modification completed");
        }
    }

    info!("Response modification completed");
    http_response
}

/// Создает HTTP ответ 403 Forbidden
fn create_403_response(reason: &str) -> Vec<u8> {
    let html_body = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Access Forbidden</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .container {{ max-width: 600px; margin: 0 auto; }}
        .error {{ color: #d32f2f; }}
        .reason {{ background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .footer {{ margin-top: 30px; font-size: 12px; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <h1 class="error">Access Forbidden</h1>
        <p>Your request has been blocked by the security policy.</p>
        <div class="reason">
            <strong>Reason:</strong> {}
        </div>
        <p>If you believe this is an error, please contact your system administrator.</p>
        <div class="footer">
            Blocked by ICAP Request Modifier v1.0
        </div>
    </div>
</body>
</html>"#,
        reason
    );

    let response = format!(
        "HTTP/1.1 403 Forbidden\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-cache, no-store, must-revalidate\r\n\
         Pragma: no-cache\r\n\
         Expires: 0\r\n\
         X-ICAP-Blocked: request-modifier-v1.0\r\n\
         X-Block-Reason: {}\r\n\
         \r\n\
         {}",
        html_body.len(),
        reason,
        html_body
    );

    response.into_bytes()
}

/// Создает ответ для заблокированного контента
fn create_blocked_content_response(reason: &str) -> Vec<u8> {
    let html_body = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Content Blocked</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .container {{ max-width: 600px; margin: 0 auto; }}
        .warning {{ color: #f57c00; }}
        .reason {{ background: #fff3e0; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #f57c00; }}
        .footer {{ margin-top: 30px; font-size: 12px; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <h1 class="warning">Content Blocked</h1>
        <p>The requested content has been blocked by the content filter.</p>
        <div class="reason">
            <strong>Reason:</strong> {}
        </div>
        <p>This action was taken to protect your security and comply with organizational policies.</p>
        <div class="footer">
            Filtered by ICAP Response Modifier v1.0
        </div>
    </div>
</body>
</html>"#,
        reason
    );

    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-cache, no-store, must-revalidate\r\n\
         Pragma: no-cache\r\n\
         Expires: 0\r\n\
         X-ICAP-Filtered: response-modifier-v1.0\r\n\
         X-Filter-Reason: {}\r\n\
         \r\n\
         {}",
        html_body.len(),
        reason,
        html_body
    );

    response.into_bytes()
}
