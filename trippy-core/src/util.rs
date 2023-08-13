use thiserror::Error;

#[derive(Error, Debug)]
#[error("required value was not supplied")]
pub struct RequiredError;

/// Required value.
pub trait Required<T> {
    fn req(self) -> Result<T, RequiredError>;
}

impl<T> Required<T> for Option<T> {
    fn req(self) -> Result<T, RequiredError> {
        self.ok_or(RequiredError)
    }
}
