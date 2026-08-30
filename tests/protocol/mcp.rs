use cog::mcp::{model::META_SECURITY_SCHEMES, tools};
use serde_json::json;
use std::collections::HashSet;

#[test]
fn native_definition_registry_is_complete_unique_and_sdk_native() {
    let definitions = tools::definitions();
    assert!(!definitions.is_empty());
    assert_eq!(
        definitions
            .iter()
            .map(|definition| definition.id)
            .collect::<HashSet<_>>()
            .len(),
        definitions.len()
    );
    assert_eq!(
        definitions
            .iter()
            .map(|definition| definition.public_name())
            .collect::<HashSet<_>>()
            .len(),
        definitions.len()
    );
    assert_eq!(
        definitions
            .iter()
            .map(|definition| definition.code_target())
            .collect::<HashSet<_>>()
            .len(),
        definitions.len()
    );
    for definition in definitions {
        assert!(!definition.title.trim().is_empty());
        assert!(!definition.description.trim().is_empty());
        assert_eq!(definition.input_schema["type"], "object");
        assert_eq!(definition.input_schema["additionalProperties"], false);
        let tool = definition.tool();
        let wire = serde_json::to_value(&tool).unwrap();
        assert!(wire.get("securitySchemes").is_none());
        assert_eq!(
            tool.meta.as_ref().unwrap()[META_SECURITY_SCHEMES][0]["scopes"],
            json!([definition.required_scope])
        );
        assert_eq!(tools::by_id(definition.id).wire_name, definition.wire_name);
        assert_eq!(
            tools::by_code_target(&definition.code_target()).unwrap().id,
            definition.id
        );
        assert_eq!(
            tools::by_public_name(&definition.public_name()).unwrap().id,
            definition.id
        );
    }
}

#[test]
fn execute_requires_explicit_integration_declarations() {
    let schema = tools::execute::definition().input_schema;
    assert_eq!(schema["required"], json!(["code", "integrations"]));
    assert_eq!(
        schema["properties"]["integrations"]["items"]["type"],
        "string"
    );
}
