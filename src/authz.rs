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

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn one_display_and_error_source() {
        let one = InsufficientScope::one("tools:call");
        assert_eq!(one.scopes, ["tools:call"]);
        assert_eq!(
            one.to_string(),
            "additional authorization required: tools:call"
        );
        assert!(one.source().is_none());

        let many = InsufficientScope {
            scopes: vec!["tools:list".into(), "tools:call".into()],
        };
        assert_eq!(
            many.to_string(),
            "additional authorization required: tools:list tools:call"
        );
        assert!(many.source().is_none());
    }
}
