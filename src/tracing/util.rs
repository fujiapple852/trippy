use std::any::type_name;
use thiserror::Error;

#[derive(Error, Debug)]
#[error("required value with id {0} was not supplied")]
pub struct RequiredError(String);

/// Required value.
pub trait Required<T> {
    fn req(self) -> Result<T, RequiredError>;
}

impl<T> Required<T> for Option<T> {
    fn req(self) -> Result<T, RequiredError> {
        self.ok_or_else(|| RequiredError(type_name::<T>().to_string()))
    }
}
