use crate::http::HttpMessage;
use std::collections::HashMap;
use std::fmt;

/// Структура ICAP запроса
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: HashMap<String, String>,
    pub http_request: Option<HttpMessage>,
    pub http_response: Option<HttpMessage>,
}

impl Request {
    /// Создает новый ICAP запрос
    pub fn new(method: &str, uri: &str, version: &str) -> Self {
        Self {
            method: method.to_string(),
            uri: uri.to_string(),
            version: version.to_string(),
            headers: HashMap::new(),
            http_request: None,
            http_response: None,
        }
    }

    /// Добавляет заголовок
    pub fn add_header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }

    /// Устанавливает HTTP запрос
    pub fn with_http_request(mut self, http_req: HttpMessage) -> Self {
        self.http_request = Some(http_req);
        self
    }

    /// Устанавливает HTTP ответ
    pub fn with_http_response(mut self, http_resp: HttpMessage) -> Self {
        self.http_response = Some(http_resp);
        self
    }

    /// Получает значение заголовка
    pub fn get_header(&self, name: &str) -> Option<&String> {
        self.headers.get(name)
    }

    /// Проверяет наличие заголовка
    pub fn has_header(&self, name: &str) -> bool {
        self.headers.contains_key(name)
    }

    /// Удаляет заголовок
    pub fn remove_header(&mut self, name: &str) -> Option<String> {
        self.headers.remove(name)
    }

    /// Проверяет, является ли запрос REQMOD
    pub fn is_reqmod(&self) -> bool {
        self.method == "REQMOD"
    }

    /// Проверяет, является ли запрос RESPMOD
    pub fn is_respmod(&self) -> bool {
        self.method == "RESPMOD"
    }

    /// Проверяет, является ли запрос OPTIONS
    pub fn is_options(&self) -> bool {
        self.method == "OPTIONS"
    }

    /// Извлекает имя сервиса из URI
    pub fn service_name(&self) -> Option<String> {
        self.uri
            .strip_prefix("icap://")
            .and_then(|uri| uri.split('/').next())
            .map(|s| s.to_string())
    }

    /// Проверяет, разрешен ли ответ 204 No Content
    ///
    /// Согласно RFC 3507, клиент может включить заголовок "Allow: 204" в запрос,
    /// указывая, что сервер может ответить с "204 No Content", если объект не нуждается в модификации.
    pub fn allows_204(&self) -> bool {
        if let Some(allow_header) = self.get_header("Allow") {
            allow_header.contains("204")
        } else {
            false
        }
    }

    /// Проверяет, является ли это предварительным просмотром (preview)
    ///
    /// В случае предварительного просмотра сервер может ответить 204 No Content
    /// даже если заголовок "Allow: 204" отсутствует.
    pub fn is_preview(&self) -> bool {
        self.has_header("Preview")
    }

    /// Проверяет, можно ли вернуть ответ 204 No Content
    ///
    /// Возвращает true если:
    /// 1. Запрос содержит заголовок "Allow: 204", или
    /// 2. Это предварительный просмотр (preview)
    pub fn can_return_204(&self) -> bool {
        self.allows_204() || self.is_preview()
    }
}

impl Default for Request {
    fn default() -> Self {
        Self {
            method: "OPTIONS".to_string(),
            uri: "icap://localhost/".to_string(),
            version: "ICAP/1.0".to_string(),
            headers: HashMap::new(),
            http_request: None,
            http_response: None,
        }
    }
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.method, self.uri, self.version)?;

        for (name, value) in &self.headers {
            write!(f, "\n{}: {}", name, value)?;
        }

        if let Some(ref http_req) = self.http_request {
            write!(f, "\n\nHTTP Request:\n{}", http_req.start_line)?;
            for (name, value) in &http_req.headers {
                write!(f, "\n{}: {}", name, value)?;
            }
            if !http_req.body.is_empty() {
                write!(f, "\n\n{}", String::from_utf8_lossy(&http_req.body))?;
            }
        }

        if let Some(ref http_resp) = self.http_response {
            write!(f, "\n\nHTTP Response:\n{}", http_resp.start_line)?;
            for (name, value) in &http_resp.headers {
                write!(f, "\n{}: {}", name, value)?;
            }
            if !http_resp.body.is_empty() {
                write!(f, "\n\n{}", String::from_utf8_lossy(&http_resp.body))?;
            }
        }

        Ok(())
    }
}
