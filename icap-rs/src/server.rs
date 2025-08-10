use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{error, trace, warn};

use crate::error::IcapResult;
use crate::icap_request::IcapRequest;
use crate::icap_response::{IcapResponse, IcapStatusCode};
use crate::options::IcapOptionsConfig;

/// Тип для обработчиков ICAP запросов
pub type IcapRequestHandler = Box<
    dyn Fn(
            IcapRequest,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = IcapResult<IcapResponse>> + Send + Sync>,
        > + Send
        + Sync,
>;

/// Основная структура ICAP сервера
pub struct IcapServer {
    listener: TcpListener,
    services: Arc<RwLock<HashMap<String, IcapRequestHandler>>>,
    options_configs: Arc<RwLock<HashMap<String, IcapOptionsConfig>>>,
}

impl IcapServer {
    /// Создает новый строитель сервера
    pub fn builder() -> IcapServerBuilder {
        IcapServerBuilder::new()
    }

    /// Запускает сервер
    pub async fn run(self) -> IcapResult<()> {
        let local_addr = self.listener.local_addr()?;
        trace!("ICAP server started on {}", local_addr);

        loop {
            let (socket, addr) = self.listener.accept().await?;
            trace!("New connection from {}", addr);

            let services = Arc::clone(&self.services);
            let options_configs = Arc::clone(&self.options_configs);
            tokio::spawn(async move {
                if let Err(e) =
                    Self::handle_connection(socket, addr, services, options_configs).await
                {
                    error!("Error handling connection {}: {}", addr, e);
                }
            });
        }
    }

    /// Обрабатывает отдельное подключение
    async fn handle_connection(
        mut socket: TcpStream,
        addr: SocketAddr,
        services: Arc<RwLock<HashMap<String, IcapRequestHandler>>>,
        options_configs: Arc<RwLock<HashMap<String, IcapOptionsConfig>>>,
    ) -> IcapResult<()> {
        let mut buffer = Vec::new();
        let mut temp_buffer = [0; 1024];

        // Читаем данные по частям, чтобы избежать блокировки
        loop {
            match socket.read(&mut temp_buffer).await {
                Ok(0) => break, // Соединение закрыто
                Ok(n) => {
                    buffer.extend_from_slice(&temp_buffer[..n]);

                    // Проверяем, есть ли полный ICAP запрос
                    if crate::parser::is_complete_icap_request(&buffer) {
                        break;
                    }
                }
                Err(e) => {
                    error!("Error reading from socket: {}", e);
                    return Err(e.into());
                }
            }
        }

        if buffer.is_empty() {
            trace!("Empty buffer received from {}", addr);
            return Ok(());
        }

        // Парсим ICAP запрос
        let request = crate::parser::parse_icap_request(&buffer)?;
        trace!("Received {} request to {}", request.method, request.uri);

        // Обрабатываем запрос в зависимости от метода
        let service_name = crate::parser::extract_service_name(&request.uri)?;

        let response = if request.method == "OPTIONS" {
            // Обрабатываем OPTIONS запрос
            let options_guard = options_configs.read().await;
            if let Some(options_config) = options_guard.get(&service_name) {
                options_config.build_response()
            } else {
                // Возвращаем базовый OPTIONS ответ, если конфигурация не найдена
                warn!(
                    "OPTIONS config for service '{}' not found, using default",
                    service_name
                );
                Self::build_default_options_response(&service_name)
            }
        } else {
            // Обрабатываем обычные ICAP запросы (REQMOD/RESPMOD)
            let services_guard = services.read().await;
            if let Some(handler) = services_guard.get(&service_name) {
                handler(request).await?
            } else {
                warn!("Service '{}' not found", service_name);
                IcapResponse::new(IcapStatusCode::NotFound404, "Service Not Found")
                    .add_header("Content-Length", "0")
            }
        };

        // Отправляем ответ
        let response_bytes = crate::parser::serialize_icap_response(&response)?;
        socket.write_all(&response_bytes).await?;
        socket.flush().await?;

        trace!("Response sent for service: {}", service_name);

        Ok(())
    }

    /// Создает базовый OPTIONS ответ для сервиса
    fn build_default_options_response(service_name: &str) -> IcapResponse {
        use crate::options::{IcapMethod, IcapOptionsConfig};

        let config = IcapOptionsConfig::new(
            vec![IcapMethod::RespMod],
            &format!("{}-default-1.0", service_name),
        )
        .with_service(&format!("Default ICAP Service for {}", service_name))
        .with_max_connections(100)
        .with_options_ttl(3600)
        .add_allow("204");

        config.build_response()
    }
}

/// Строитель для ICAP сервера
pub struct IcapServerBuilder {
    bind_addr: Option<String>,
    services: HashMap<String, IcapRequestHandler>,
    options_configs: HashMap<String, IcapOptionsConfig>,
}

impl IcapServerBuilder {
    /// Создает новый строитель сервера
    pub fn new() -> Self {
        Self {
            bind_addr: None,
            services: HashMap::new(),
            options_configs: HashMap::new(),
        }
    }

    /// Устанавливает адрес для привязки
    pub fn bind(mut self, addr: &str) -> Self {
        self.bind_addr = Some(addr.to_string());
        self
    }

    /// Добавляет сервис
    pub fn add_service<F, Fut>(mut self, name: &str, handler: F) -> Self
    where
        F: Fn(IcapRequest) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = IcapResult<IcapResponse>> + Send + Sync + 'static,
    {
        let handler: IcapRequestHandler = Box::new(move |req| {
            let fut = handler(req);
            Box::pin(fut)
        });
        self.services.insert(name.to_string(), handler);
        self
    }

    /// Добавляет OPTIONS конфигурацию для сервиса
    pub fn add_options_config(mut self, name: &str, config: IcapOptionsConfig) -> Self {
        self.options_configs.insert(name.to_string(), config);
        self
    }

    /// Строит ICAP сервер
    pub async fn build(self) -> IcapResult<IcapServer> {
        let bind_addr = self
            .bind_addr
            .unwrap_or_else(|| "127.0.0.1:1344".to_string());
        let listener = tokio::net::TcpListener::bind(&bind_addr).await?;

        let services = Arc::new(RwLock::new(self.services));
        let options_configs = Arc::new(RwLock::new(self.options_configs));

        Ok(IcapServer {
            listener,
            services,
            options_configs,
        })
    }
}

impl Default for IcapServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
