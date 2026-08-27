#[derive(Debug, Clone)]
pub struct InsufficientScope {
    pub scopes: Vec<String>,
}

impl InsufficientScope {
    pub fn one(scope: impl Into<String>) -> Self {
        Self {
            scopes: vec![scope.into()],
        }
    }
}

impl std::fmt::Display for InsufficientScope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "additional authorization required: {}",
            self.scopes.join(" ")
        )
    }
}

impl std::error::Error for InsufficientScope {}
