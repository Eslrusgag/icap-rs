use std::error::{Error as StdError, Error};
use thiserror::Error;

/// Основной тип ошибки для ICAP библиотеки
#[derive(Error, Debug)]
pub enum IcapError {
    /// Ошибка сети (TCP соединение, таймаут и т.д.)
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    /// Ошибка парсинга ICAP сообщения
    #[error("ICAP parsing error: {0}")]
    Parse(String),

    /// Ошибка HTTP парсинга
    #[error("HTTP parsing error: {0}")]
    HttpParse(String),

    /// Неверный статус код
    #[error("Invalid status code: {0}")]
    InvalidStatusCode(String),

    /// Неверный метод
    #[error("Invalid method: {0}")]
    InvalidMethod(String),

    /// Неверный URI
    #[error("Invalid URI: {0}")]
    InvalidUri(String),

    /// Неверная версия протокола
    #[error("Invalid protocol version: {0}")]
    InvalidVersion(String),

    /// Ошибка заголовка
    #[error("Header error: {0}")]
    Header(String),

    /// Ошибка тела сообщения
    #[error("Body error: {0}")]
    Body(String),

    /// Ошибка сервиса
    #[error("Service error: {0}")]
    Service(String),

    /// Ошибка конфигурации
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Ошибка обработчика
    #[error("Handler error: {0}")]
    Handler(String),

    /// Ошибка сериализации
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Ошибка десериализации
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// Неизвестная ошибка
    #[error("Unexpected error: {0}")]
    Unexpected(String),
}

impl IcapError {
    /// Создает ошибку парсинга
    pub fn parse(message: impl Into<String>) -> Self {
        Self::Parse(message.into())
    }

    /// Создает ошибку HTTP парсинга
    pub fn http_parse(message: impl Into<String>) -> Self {
        Self::HttpParse(message.into())
    }

    /// Создает ошибку заголовка
    pub fn header(message: impl Into<String>) -> Self {
        Self::Header(message.into())
    }

    /// Создает ошибку тела сообщения
    pub fn body(message: impl Into<String>) -> Self {
        Self::Body(message.into())
    }

    /// Создает ошибку сервиса
    pub fn service(message: impl Into<String>) -> Self {
        Self::Service(message.into())
    }

    /// Создает ошибку конфигурации
    pub fn configuration(message: impl Into<String>) -> Self {
        Self::Configuration(message.into())
    }

    /// Создает ошибку обработчика
    pub fn handler(message: impl Into<String>) -> Self {
        Self::Handler(message.into())
    }

    /// Создает ошибку сериализации
    pub fn serialization(message: impl Into<String>) -> Self {
        Self::Serialization(message.into())
    }

    /// Создает ошибку десериализации
    pub fn deserialization(message: impl Into<String>) -> Self {
        Self::Deserialization(message.into())
    }

    /// Создает неизвестную ошибку
    pub fn unknown(message: impl Into<String>) -> Self {
        Self::Unexpected(message.into())
    }
}

impl From<String> for IcapError {
    fn from(err: String) -> Self {
        Self::Unexpected(err)
    }
}

impl From<&str> for IcapError {
    fn from(err: &str) -> Self {
        Self::Unexpected(err.to_string())
    }
}

impl From<Box<dyn Error + Send + Sync>> for IcapError {
    fn from(err: Box<dyn Error + Send + Sync>) -> Self {
        Self::Unexpected(err.to_string())
    }
}

/// Результат операций ICAP
pub type IcapResult<T> = Result<T, IcapError>;

/// Конвертирует стандартный Result в IcapResult
pub trait ToIcapResult<T> {
    fn to_icap_result(self) -> IcapResult<T>;
}

impl<T, E> ToIcapResult<T> for Result<T, E>
where
    E: StdError + Send + Sync + 'static,
{
    fn to_icap_result(self) -> IcapResult<T> {
        self.map_err(|e| IcapError::Unexpected(e.to_string()))
    }
}

/// Макрос для создания ошибок парсинга
#[macro_export]
macro_rules! icap_parse_error {
    ($($arg:tt)*) => {
        $crate::error::IcapError::parse(format!($($arg)*))
    };
}

/// Макрос для создания ошибок HTTP парсинга
#[macro_export]
macro_rules! icap_http_error {
    ($($arg:tt)*) => {
        $crate::error::IcapError::http_parse(format!($($arg)*))
    };
}

/// Макрос для создания ошибок заголовков
#[macro_export]
macro_rules! icap_header_error {
    ($($arg:tt)*) => {
        $crate::error::IcapError::header(format!($($arg)*))
    };
}

/// Макрос для создания ошибок сервиса
#[macro_export]
macro_rules! icap_service_error {
    ($($arg:tt)*) => {
        $crate::error::IcapError::service(format!($($arg)*))
    };
}

/// Макрос для создания ошибок конфигурации
#[macro_export]
macro_rules! icap_config_error {
    ($($arg:tt)*) => {
        $crate::error::IcapError::configuration(format!($($arg)*))
    };
}
