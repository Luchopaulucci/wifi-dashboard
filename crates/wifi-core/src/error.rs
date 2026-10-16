use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("argumento inválido ({0})")]
    InvalidArg(String),
    #[error("comando no permitido: {0}")]
    CommandNotAllowed(String),
    #[error("falló {comando}: {detalle}")]
    CommandFailed { comando: String, detalle: String },
    #[error("no se encontró el binario {0}")]
    BinaryMissing(String),
    #[error("almacenamiento: {0}")]
    Storage(String),
    #[error("parseo: {0}")]
    Parse(String),
    #[error("operación no permitida: {0}")]
    Forbidden(String),
}

pub type Result<T> = std::result::Result<T, CoreError>;
