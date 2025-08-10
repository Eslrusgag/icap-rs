use icap_rs::{
    HttpMessageTrait, IcapMethod, IcapOptionsBuilder, IcapRequest, IcapResponse, IcapServer,
    IcapStatusCode, TransferBehavior, error::IcapError,
};
use tokio;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Инициализируем логирование
    tracing_subscriber::fmt::init();

    // Создаем OPTIONS конфигурацию для сервиса content-filter
    let content_filter_options =
        IcapOptionsBuilder::new(vec![IcapMethod::RespMod], "content-filter-v2.1")
            .service("Example Content Filter Service 2.1")
            .max_connections(1000)
            .options_ttl(7200)
            .with_current_date()
            .service_id("content-filter")
            .allow_204()
            .preview(2048)
            .transfer_rule("html", TransferBehavior::Ignore)
            .transfer_rule("css", TransferBehavior::Ignore)
            .transfer_rule("js", TransferBehavior::Ignore)
            .transfer_rule("exe", TransferBehavior::Complete)
            .transfer_rule("bat", TransferBehavior::Complete)
            .transfer_rule("com", TransferBehavior::Complete)
            .transfer_rule("asp", TransferBehavior::Complete)
            .default_transfer_behavior(TransferBehavior::Preview)
            .custom_header("X-Filter-Version", "2.1.0")
            .custom_header("X-Vendor", "Example Corp")
            .build()?;

    // Создаем OPTIONS конфигурацию для сервиса virus-scan
    let virus_scan_options = IcapOptionsBuilder::new(
        vec![IcapMethod::ReqMod, IcapMethod::RespMod],
        "virus-scan-v3.0",
    )
    .service("Example Virus Scanner 3.0")
    .max_connections(500)
    .options_ttl(3600)
    .with_current_date()
    .service_id("virus-scan")
    .allow_204()
    .preview(1024)
    .transfer_rule("txt", TransferBehavior::Ignore)
    .transfer_rule("css", TransferBehavior::Ignore)
    .transfer_rule("js", TransferBehavior::Ignore)
    .default_transfer_behavior(TransferBehavior::Preview)
    .custom_header("X-Scanner-Engine", "ExampleAV v3.0")
    .build()?;

    // Создаем сервер с сервисами и их OPTIONS конфигурациями
    let server = IcapServer::builder()
        .bind("127.0.0.1:1344")
        .add_service("content-filter", content_filter_handler)
        .add_options_config("content-filter", content_filter_options)
        .add_service("virus-scan", virus_scan_handler)
        .add_options_config("virus-scan", virus_scan_options)
        .build()
        .await?;

    info!("ICAP server with OPTIONS support started on 127.0.0.1:1344");
    info!("Available services:");
    info!("  - icap://127.0.0.1:1344/content-filter (RESPMOD)");
    info!("  - icap://127.0.0.1:1344/virus-scan (REQMOD/RESPMOD)");
    info!("");
    info!("Try OPTIONS requests:");
    info!("  curl -X OPTIONS http://127.0.0.1:1344/content-filter");
    info!("  curl -X OPTIONS http://127.0.0.1:1344/virus-scan");

    // Запускаем сервер
    server.run().await.map_err(|e| e.into())
}

/// Обработчик для сервиса content-filter
async fn content_filter_handler(request: IcapRequest) -> Result<IcapResponse, IcapError> {
    info!("Content filter processing request: {}", request.method);

    match request.method.as_str() {
        "RESPMOD" => {
            // Имитируем фильтрацию содержимого
            if let Some(http_resp) = request.http_response {
                info!("Filtering HTTP response: {}", http_resp.start_line);

                // Проверяем Content-Type
                if let Some(content_type) = http_resp.get_header("Content-Type") {
                    if content_type.contains("text/html") {
                        info!("HTML content detected, applying content filter");

                        // Возвращаем модифицированный ответ
                        let mut filtered_response = http_resp.clone();
                        let filtered_body = String::from_utf8_lossy(&http_resp.body)
                            .replace("<script", "<!-- script")
                            .replace("</script>", " -->");
                        filtered_response.body = filtered_body.into_bytes();

                        let icap_response = IcapResponse::new(IcapStatusCode::Ok200, "OK")
                            .add_header("ISTag", "\"content-filter-v2.1\"")
                            .add_header("Encapsulated", "res-hdr=0, res-body=100")
                            .with_body(&filtered_response.to_raw());

                        return Ok(icap_response);
                    }
                }
            }

            // Возвращаем 204 No Content (не требует модификации)
            Ok(
                IcapResponse::new(IcapStatusCode::NoContent204, "No Content")
                    .add_header("ISTag", "\"content-filter-v2.1\""),
            )
        }
        _ => Ok(IcapResponse::new(
            IcapStatusCode::MethodNotAllowed405,
            "Method Not Allowed",
        )),
    }
}

/// Обработчик для сервиса virus-scan
async fn virus_scan_handler(request: IcapRequest) -> Result<IcapResponse, IcapError> {
    info!("Virus scanner processing request: {}", request.method);

    match request.method.as_str() {
        "REQMOD" => {
            info!("Scanning HTTP request");

            // Имитируем сканирование запроса
            if let Some(http_req) = request.http_request {
                info!("Scanning request to: {}", http_req.start_line);

                // Проверяем наличие подозрительных паттернов в URL
                if http_req.start_line.contains("malware") || http_req.start_line.contains("virus")
                {
                    info!("Suspicious request detected, blocking");

                    // Возвращаем блокирующий ответ
                    let block_response = format!(
                        "HTTP/1.1 403 Forbidden\r\n\
                         Content-Type: text/html\r\n\
                         Content-Length: 43\r\n\
                         \r\n\
                         <html><body>Access blocked by virus scanner</body></html>"
                    );

                    return Ok(IcapResponse::new(IcapStatusCode::Ok200, "OK")
                        .add_header("ISTag", "\"virus-scan-v3.0\"")
                        .add_header("Encapsulated", "res-hdr=0, res-body=100")
                        .with_body(block_response.as_bytes()));
                }
            }

            // Запрос чист
            Ok(
                IcapResponse::new(IcapStatusCode::NoContent204, "No Content")
                    .add_header("ISTag", "\"virus-scan-v3.0\""),
            )
        }
        "RESPMOD" => {
            info!("Scanning HTTP response");

            // Имитируем сканирование ответа
            if let Some(http_resp) = request.http_response {
                info!("Scanning response: {}", http_resp.start_line);

                // Проверяем размер файла
                if http_resp.body.len() > 10 * 1024 * 1024 {
                    // 10MB
                    info!("Large file detected, requires full scan");

                    // В реальной реализации здесь был бы полный скан
                    // Для примера просто возвращаем 204
                }
            }

            Ok(
                IcapResponse::new(IcapStatusCode::NoContent204, "No Content")
                    .add_header("ISTag", "\"virus-scan-v3.0\""),
            )
        }
        _ => Ok(IcapResponse::new(
            IcapStatusCode::MethodNotAllowed405,
            "Method Not Allowed",
        )),
    }
}
