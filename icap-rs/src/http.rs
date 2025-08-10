use std::collections::HashMap;

/// Трейт для HTTP сообщений (запросы и ответы)
pub trait HttpMessageTrait {
    /// Получает стартовую строку
    fn start_line(&self) -> &str;

    /// Получает заголовки
    fn headers(&self) -> &HashMap<String, String>;

    /// Получает тело сообщения
    fn body(&self) -> &[u8];

    /// Добавляет заголовок
    fn add_header(&mut self, name: &str, value: &str);

    /// Получает значение заголовка
    fn get_header(&self, name: &str) -> Option<&String> {
        self.headers().get(name)
    }

    /// Проверяет наличие заголовка
    fn has_header(&self, name: &str) -> bool {
        self.headers().contains_key(name)
    }

    /// Удаляет заголовок
    fn remove_header(&mut self, name: &str) -> Option<String>;

    /// Устанавливает тело сообщения
    fn set_body(&mut self, body: &[u8]);

    /// Устанавливает тело сообщения из строки
    fn set_body_string(&mut self, body: &str) {
        self.set_body(body.as_bytes());
    }

    /// Конвертирует в сырые байты
    fn to_raw(&self) -> Vec<u8> {
        let mut raw = Vec::new();

        // Start line
        raw.extend_from_slice(format!("{}\r\n", self.start_line()).as_bytes());

        // Headers
        for (name, value) in self.headers() {
            raw.extend_from_slice(format!("{}: {}\r\n", name, value).as_bytes());
        }

        // Empty line before body
        raw.extend_from_slice(b"\r\n");

        // Body
        if !self.body().is_empty() {
            raw.extend_from_slice(self.body());
        }

        raw
    }
}

/// Строитель для HTTP сообщений
pub struct HttpMessageBuilder {
    start_line: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl HttpMessageBuilder {
    /// Создает новый строитель
    pub fn new(start_line: &str) -> Self {
        Self {
            start_line: start_line.to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    /// Добавляет заголовок
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }

    /// Добавляет заголовки из строки
    pub fn headers_from_string(mut self, headers_str: &str) -> Self {
        for line in headers_str.lines() {
            if let Some((name, value)) = line.split_once(':') {
                let name = name.trim();
                let value = value.trim();
                if !name.is_empty() && !value.is_empty() {
                    self.headers.insert(name.to_string(), value.to_string());
                }
            }
        }
        self
    }

    /// Устанавливает тело
    pub fn body(mut self, body: &[u8]) -> Self {
        self.body = body.to_vec();
        self
    }

    /// Устанавливает тело из строки
    pub fn body_string(mut self, body: &str) -> Self {
        self.body = body.as_bytes().to_vec();
        self
    }

    /// Строит HTTP сообщение
    pub fn build(self) -> HttpMessage {
        HttpMessage {
            start_line: self.start_line,
            headers: self.headers,
            body: self.body,
        }
    }
}

/// HTTP сообщение (запрос или ответ)
#[derive(Debug, Clone)]
pub struct HttpMessage {
    pub start_line: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpMessage {
    /// Создает новое HTTP сообщение
    pub fn new(start_line: &str) -> Self {
        Self {
            start_line: start_line.to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    /// Создает строитель для HTTP сообщения
    pub fn builder(start_line: &str) -> HttpMessageBuilder {
        HttpMessageBuilder::new(start_line)
    }

    /// Добавляет заголовок
    pub fn add_header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }

    /// Устанавливает тело сообщения
    pub fn with_body(mut self, body: &[u8]) -> Self {
        self.body = body.to_vec();
        self
    }

    /// Устанавливает тело сообщения из строки
    pub fn with_body_string(mut self, body: &str) -> Self {
        self.body = body.as_bytes().to_vec();
        self
    }
}

impl HttpMessageTrait for HttpMessage {
    fn start_line(&self) -> &str {
        &self.start_line
    }

    fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    fn body(&self) -> &[u8] {
        &self.body
    }

    fn add_header(&mut self, name: &str, value: &str) {
        self.headers.insert(name.to_string(), value.to_string());
    }

    fn remove_header(&mut self, name: &str) -> Option<String> {
        self.headers.remove(name)
    }

    fn set_body(&mut self, body: &[u8]) {
        self.body = body.to_vec();
    }
}

/// HTTP сессия для клиентских запросов
#[derive(Debug, Clone)]
pub struct HttpSession {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpSession {
    /// Создает новую HTTP сессию
    pub fn new(method: &str, path: &str) -> Self {
        Self {
            method: method.to_string(),
            path: path.to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    /// Добавляет заголовок
    pub fn add_header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }

    /// Добавляет заголовки из строки
    pub fn add_headers_from_string(mut self, headers_str: &str) -> Self {
        for line in headers_str.lines() {
            if let Some((name, value)) = line.split_once(':') {
                let name = name.trim();
                let value = value.trim();
                if !name.is_empty() && !value.is_empty() {
                    self.headers.insert(name.to_string(), value.to_string());
                }
            }
        }
        self
    }

    /// Устанавливает тело
    pub fn with_body(mut self, body: &[u8]) -> Self {
        self.body = body.to_vec();
        self
    }

    /// Устанавливает тело из строки
    pub fn with_body_string(mut self, body: &str) -> Self {
        self.body = body.as_bytes().to_vec();
        self
    }

    /// Конвертирует в сырые байты HTTP запроса
    pub fn to_raw(&self) -> Vec<u8> {
        let mut raw = Vec::new();

        // Request line
        raw.extend_from_slice(format!("{} {} HTTP/1.1\r\n", self.method, self.path).as_bytes());

        // Headers
        for (name, value) in &self.headers {
            raw.extend_from_slice(format!("{}: {}\r\n", name, value).as_bytes());
        }

        // Add Transfer-Encoding: chunked if not present
        if !self.headers.contains_key("Transfer-Encoding") {
            raw.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        }

        // Empty line before body
        raw.extend_from_slice(b"\r\n");

        // Body with chunked encoding
        if !self.body.is_empty() {
            let chunk_size = format!("{:x}\r\n", self.body.len());
            raw.extend_from_slice(chunk_size.as_bytes());
            raw.extend_from_slice(&self.body);
            raw.extend_from_slice(b"\r\n");
        }

        // End chunk
        raw.extend_from_slice(b"0\r\n\r\n");

        raw
    }

    /// Конвертирует в HttpMessage
    pub fn to_http_message(&self) -> HttpMessage {
        let start_line = format!("{} {} HTTP/1.1", self.method, self.path);
        HttpMessage {
            start_line,
            headers: self.headers.clone(),
            body: self.body.clone(),
        }
    }
}
