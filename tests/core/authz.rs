use cog::authz::*;
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
