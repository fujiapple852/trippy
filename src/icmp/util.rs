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

/// TODO
pub trait RemModU16Max {
    /// Return the remainder modulo `u16::MAX`.
    fn rem_u16max(self) -> u16;
}

impl RemModU16Max for usize {
    fn rem_u16max(self) -> u16 {
        u16::try_from(self % Self::from(u16::MAX)).unwrap()
    }
}
