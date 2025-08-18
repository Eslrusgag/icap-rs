use crate::response::{Response, StatusCode};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::fmt;

/// ICAP методы, поддерживаемые сервисом
#[derive(Debug, Clone, PartialEq)]
pub enum IcapMethod {
    ReqMod,
    RespMod,
}

impl fmt::Display for IcapMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IcapMethod::ReqMod => write!(f, "REQMOD"),
            IcapMethod::RespMod => write!(f, "RESPMOD"),
        }
    }
}

/// Поведение для расширений файлов в Transfer-* заголовках
#[derive(Debug, Clone, PartialEq)]
pub enum TransferBehavior {
    /// Файлы должны быть отправлены с preview
    Preview,
    /// Файлы должны быть проигнорированы
    Ignore,
    /// Файлы должны быть отправлены полностью без preview
    Complete,
}

/// Конфигурация OPTIONS для ICAP сервиса
#[derive(Debug, Clone)]
pub struct OptionsConfig {
    /// Методы, поддерживаемые этим сервисом (ОБЯЗАТЕЛЬНЫЙ)
    pub methods: Vec<IcapMethod>,

    /// Описание сервиса
    pub service: Option<String>,

    /// ISTag - уникальный идентификатор конфигурации сервиса (ОБЯЗАТЕЛЬНЫЙ)
    pub istag: String,

    /// Максимальное количество соединений
    pub max_connections: Option<u32>,

    /// Время жизни OPTIONS ответа в секундах
    pub options_ttl: Option<u32>,

    /// Дата сервера
    pub date: Option<DateTime<Utc>>,

    /// Короткий идентификатор сервиса
    pub service_id: Option<String>,

    /// Список поддерживаемых возможностей (ОПЦИОНАЛЬНЫЙ)
    /// Например: "204" для поддержки 204 ответа
    pub allow: Vec<String>,

    /// Размер preview в байтах
    pub preview: Option<u32>,

    /// Поведение для различных расширений файлов
    pub transfer_rules: HashMap<String, TransferBehavior>,

    /// Поведение по умолчанию для файлов (должно быть установлено если есть transfer_rules)
    pub default_transfer_behavior: Option<TransferBehavior>,

    /// Дополнительные пользовательские заголовки
    pub custom_headers: HashMap<String, String>,

    /// Opt-body тип (если присутствует opt-body)
    pub opt_body_type: Option<String>,

    /// Opt-body содержимое
    pub opt_body: Option<Vec<u8>>,
}

impl OptionsConfig {
    /// Создает новую конфигурацию OPTIONS с минимальными обязательными параметрами
    pub fn new(methods: Vec<IcapMethod>, istag: &str) -> Self {
        Self {
            methods,
            service: None,
            istag: istag.to_string(),
            max_connections: None,
            options_ttl: None,
            date: None,
            service_id: None,
            allow: Vec::new(),
            preview: None,
            transfer_rules: HashMap::new(),
            default_transfer_behavior: None,
            custom_headers: HashMap::new(),
            opt_body_type: None,
            opt_body: None,
        }
    }

    /// Устанавливает описание сервиса
    pub fn with_service(mut self, service: &str) -> Self {
        self.service = Some(service.to_string());
        self
    }

    /// Устанавливает максимальное количество соединений
    pub fn with_max_connections(mut self, max_connections: u32) -> Self {
        self.max_connections = Some(max_connections);
        self
    }

    /// Устанавливает время жизни OPTIONS ответа
    pub fn with_options_ttl(mut self, ttl: u32) -> Self {
        self.options_ttl = Some(ttl);
        self
    }

    /// Устанавливает дату сервера
    pub fn with_date(mut self, date: DateTime<Utc>) -> Self {
        self.date = Some(date);
        self
    }

    /// Устанавливает идентификатор сервиса
    pub fn with_service_id(mut self, service_id: &str) -> Self {
        self.service_id = Some(service_id.to_string());
        self
    }

    /// Добавляет поддерживаемую возможность
    pub fn add_allow(mut self, capability: &str) -> Self {
        self.allow.push(capability.to_string());
        self
    }

    /// Устанавливает размер preview
    pub fn with_preview(mut self, preview: u32) -> Self {
        self.preview = Some(preview);
        self
    }

    /// Добавляет правило для расширения файла
    pub fn add_transfer_rule(mut self, extension: &str, behavior: TransferBehavior) -> Self {
        self.transfer_rules.insert(extension.to_string(), behavior);
        self
    }

    /// Устанавливает поведение по умолчанию для файлов
    pub fn with_default_transfer_behavior(mut self, behavior: TransferBehavior) -> Self {
        self.default_transfer_behavior = Some(behavior);
        self
    }

    /// Добавляет пользовательский заголовок
    pub fn add_custom_header(mut self, name: &str, value: &str) -> Self {
        self.custom_headers
            .insert(name.to_string(), value.to_string());
        self
    }

    /// Устанавливает opt-body
    pub fn with_opt_body(mut self, body_type: &str, body: Vec<u8>) -> Self {
        self.opt_body_type = Some(body_type.to_string());
        self.opt_body = Some(body);
        self
    }

    /// Создает ICAP ответ на основе конфигурации
    pub fn build_response(&self) -> Response {
        let mut response = Response::new(StatusCode::Ok200, "OK");

        // Обязательные заголовки

        // Methods (ОБЯЗАТЕЛЬНЫЙ)
        let methods_str = self
            .methods
            .iter()
            .map(|m| m.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        response = response.add_header("Methods", &methods_str);

        // ISTag (ОБЯЗАТЕЛЬНЫЙ)
        response = response.add_header("ISTag", &format!("\"{}\"", self.istag));

        // Encapsulated (ОБЯЗАТЕЛЬНЫЙ)
        let encapsulated_value = if self.opt_body.is_some() {
            "opt-body=0"
        } else {
            "null-body=0"
        };
        response = response.add_header("Encapsulated", encapsulated_value);

        // Опциональные заголовки

        if let Some(ref service) = self.service {
            response = response.add_header("Service", service);
        }

        if let Some(max_conn) = self.max_connections {
            response = response.add_header("Max-Connections", &max_conn.to_string());
        }

        if let Some(ttl) = self.options_ttl {
            response = response.add_header("Options-TTL", &ttl.to_string());
        }

        if let Some(date) = self.date {
            response = response.add_header(
                "Date",
                &date.format("%a, %d %b %Y %H:%M:%S GMT").to_string(),
            );
        }

        if let Some(ref service_id) = self.service_id {
            response = response.add_header("Service-ID", service_id);
        }

        if !self.allow.is_empty() {
            response = response.add_header("Allow", &self.allow.join(", "));
        }

        if let Some(preview) = self.preview {
            response = response.add_header("Preview", &preview.to_string());
        }

        if let Some(ref opt_body_type) = self.opt_body_type {
            response = response.add_header("Opt-body-type", opt_body_type);
        }

        // Transfer-* заголовки
        if !self.transfer_rules.is_empty() {
            let mut preview_extensions = Vec::new();
            let mut ignore_extensions = Vec::new();
            let mut complete_extensions = Vec::new();

            for (ext, behavior) in &self.transfer_rules {
                match behavior {
                    TransferBehavior::Preview => preview_extensions.push(ext.clone()),
                    TransferBehavior::Ignore => ignore_extensions.push(ext.clone()),
                    TransferBehavior::Complete => complete_extensions.push(ext.clone()),
                }
            }

            // Добавляем поведение по умолчанию
            if let Some(ref default_behavior) = self.default_transfer_behavior {
                match default_behavior {
                    TransferBehavior::Preview => preview_extensions.push("*".to_string()),
                    TransferBehavior::Ignore => ignore_extensions.push("*".to_string()),
                    TransferBehavior::Complete => complete_extensions.push("*".to_string()),
                }
            }

            if !preview_extensions.is_empty() {
                response = response.add_header("Transfer-Preview", &preview_extensions.join(", "));
            }

            if !ignore_extensions.is_empty() {
                response = response.add_header("Transfer-Ignore", &ignore_extensions.join(", "));
            }

            if !complete_extensions.is_empty() {
                response =
                    response.add_header("Transfer-Complete", &complete_extensions.join(", "));
            }
        }

        // Пользовательские заголовки
        for (name, value) in &self.custom_headers {
            response = response.add_header(name, value);
        }

        // Opt-body
        if let Some(ref opt_body) = self.opt_body {
            response = response.with_body(opt_body);
        }

        response
    }

    /// Валидирует конфигурацию
    pub fn validate(&self) -> Result<(), String> {
        if self.methods.is_empty() {
            return Err("Methods list cannot be empty".to_string());
        }

        if self.istag.is_empty() {
            return Err("ISTag cannot be empty".to_string());
        }

        // Проверяем, что если есть transfer_rules, то должно быть поведение по умолчанию
        if !self.transfer_rules.is_empty() && self.default_transfer_behavior.is_none() {
            return Err(
                "Default transfer behavior must be set when transfer rules are defined".to_string(),
            );
        }

        // Проверяем, что если есть opt_body, то должен быть opt_body_type
        if self.opt_body.is_some() && self.opt_body_type.is_none() {
            return Err("Opt-body-type must be set when opt-body is present".to_string());
        }

        Ok(())
    }
}

impl Default for OptionsConfig {
    fn default() -> Self {
        Self::new(vec![IcapMethod::RespMod], "default-service-tag-1.0")
    }
}

/// Строитель для OptionsConfig
pub struct IcapOptionsBuilder {
    config: OptionsConfig,
}

impl IcapOptionsBuilder {
    /// Создает новый строитель
    pub fn new(methods: Vec<IcapMethod>, istag: &str) -> Self {
        Self {
            config: OptionsConfig::new(methods, istag),
        }
    }

    /// Устанавливает описание сервиса
    pub fn service(mut self, service: &str) -> Self {
        self.config = self.config.with_service(service);
        self
    }

    /// Устанавливает максимальное количество соединений
    pub fn max_connections(mut self, max_connections: u32) -> Self {
        self.config = self.config.with_max_connections(max_connections);
        self
    }

    /// Устанавливает время жизни OPTIONS ответа
    pub fn options_ttl(mut self, ttl: u32) -> Self {
        self.config = self.config.with_options_ttl(ttl);
        self
    }

    /// Устанавливает дату сервера (по умолчанию текущая)
    pub fn with_current_date(mut self) -> Self {
        self.config = self.config.with_date(Utc::now());
        self
    }

    /// Устанавливает идентификатор сервиса
    pub fn service_id(mut self, service_id: &str) -> Self {
        self.config = self.config.with_service_id(service_id);
        self
    }

    /// Добавляет поддержку 204 ответа
    pub fn allow_204(mut self) -> Self {
        self.config = self.config.add_allow("204");
        self
    }

    /// Устанавливает размер preview
    pub fn preview(mut self, preview: u32) -> Self {
        self.config = self.config.with_preview(preview);
        self
    }

    /// Добавляет правило для расширения файла
    pub fn transfer_rule(mut self, extension: &str, behavior: TransferBehavior) -> Self {
        self.config = self.config.add_transfer_rule(extension, behavior);
        self
    }

    /// Устанавливает поведение по умолчанию для файлов
    pub fn default_transfer_behavior(mut self, behavior: TransferBehavior) -> Self {
        self.config = self.config.with_default_transfer_behavior(behavior);
        self
    }

    /// Добавляет пользовательский заголовок
    pub fn custom_header(mut self, name: &str, value: &str) -> Self {
        self.config = self.config.add_custom_header(name, value);
        self
    }

    /// Строит финальную конфигурацию
    pub fn build(self) -> Result<OptionsConfig, String> {
        self.config.validate()?;
        Ok(self.config)
    }
}
