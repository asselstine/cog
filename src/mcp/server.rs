use super::{
    catalog::Catalog,
    model::{CallToolResult, ContentBlock},
    service::catalog,
    tools::{self, NativeToolId},
};
use crate::{
    authz::InsufficientScope,
    server::{App, AuthContext},
};
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    model::{
        CallToolRequestMethod, CallToolRequestParams, CallToolResponse, DiscoverResult,
        Implementation, InitializeRequestParams, InitializeResult, ListToolsResult,
        PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerInfo,
    },
    service::RequestContext,
};
use serde_json::{Value, json};
use std::{collections::HashSet, sync::Arc};

const HYBRID_INSTRUCTIONS: &str = "External integration tools are available through execute and Cog-native tools are advertised directly. The execute request must declare every immutable integration ID it may access in arguments.integrations. For Git, call repository_access, reuse an existing Ed25519 identity, register only its public key with ssh_key_register, and renew its internal lease with ssh_key_lease_renew. Pin knownHosts and use sshRemoteUrl. Never send the private key, generate a key automatically, or disable host-key checking.";

#[derive(Clone)]
pub struct CogServer {
    app: App,
}

impl CogServer {
    pub fn new(app: App) -> Self {
        Self { app }
    }

    fn request_parts(
        context: &RequestContext<RoleServer>,
    ) -> Result<&http::request::Parts, ErrorData> {
        context
            .extensions
            .get::<http::request::Parts>()
            .ok_or_else(|| ErrorData::internal_error("HTTP request context missing", None))
    }

    fn request_auth(context: &RequestContext<RoleServer>) -> Result<&AuthContext, ErrorData> {
        Self::request_parts(context)?
            .extensions
            .get::<AuthContext>()
            .ok_or_else(|| ErrorData::internal_error("authenticated identity missing", None))
    }

    fn codemode(context: &RequestContext<RoleServer>) -> bool {
        Self::request_parts(context)
            .ok()
            .and_then(|parts| parts.uri.query())
            .is_some_and(|query| {
                query
                    .split('&')
                    .any(|part| part == "codemode=true" || part == "codemode=1")
            })
    }

    fn success(value: Value) -> CallToolResponse {
        let text = serde_json::to_string(&value).expect("tool result serializes");
        let structured = if value.is_object() {
            value
        } else {
            json!({"result":value})
        };
        let mut result = CallToolResult::structured(structured);
        result.content = vec![ContentBlock::text(text)];
        result.into()
    }

    fn corrective_error(message: impl Into<String>) -> CallToolResponse {
        let message = message.into();
        let mut result = CallToolResult::error(vec![ContentBlock::text(message.clone())]);
        result.structured_content = Some(json!({"error":{"message":message,"corrective":true}}));
        result.into()
    }

    fn tool_error(error: anyhow::Error, resource_metadata: &str) -> CallToolResponse {
        match error.downcast_ref::<InsufficientScope>() {
            Some(required) => Self::scope_error(&required.scopes, resource_metadata),
            None => Self::corrective_error(error.to_string()),
        }
    }

    fn scope_error(scopes: &[String], resource_metadata_url: &str) -> CallToolResponse {
        let mut required = vec!["mcp".to_owned()];
        required.extend(
            scopes
                .iter()
                .filter(|scope| scope.as_str() != "mcp")
                .cloned(),
        );
        let scope = required.join(" ");
        let challenge = format!(
            "Bearer resource_metadata=\"{resource_metadata_url}\", error=\"insufficient_scope\", error_description=\"Additional authorization is required\", scope=\"{scope}\""
        );
        let message = format!(
            "Additional downstream authorization is required for scope: {scope}. Reauthorize and refresh this same MCP client's credential. Do not use integration_reconnect; it replaces upstream provider credentials and cannot grant this client access."
        );
        let mut result = CallToolResult::error(vec![ContentBlock::text(message)]);
        result.structured_content = Some(
            json!({"error":"insufficient_scope","requiredScopes":required,"action":"reauthorizeSameClient","prohibitedAction":"integration_reconnect"}),
        );
        let mut meta = rmcp::model::MetaObject::new();
        meta.insert("mcp/www_authenticate".to_owned(), json!([challenge]));
        result.meta = Some(meta);
        result.into()
    }
}

impl ServerHandler for CogServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("cog", env!("CARGO_PKG_VERSION")).with_title("Cog"),
            )
            .with_instructions(HYBRID_INSTRUCTIONS)
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, ErrorData> {
        context.peer.set_peer_info(request.clone());
        let mut info = self.get_info();
        if ProtocolVersion::KNOWN_VERSIONS.contains(&request.protocol_version) {
            info.protocol_version = request.protocol_version;
        }
        info.instructions = Some(
            if Self::codemode(&context) {
                tools::execute::INSTRUCTIONS
            } else {
                HYBRID_INSTRUCTIONS
            }
            .to_owned(),
        );
        Ok(info)
    }

    async fn discover(
        &self,
        context: RequestContext<RoleServer>,
    ) -> Result<DiscoverResult, ErrorData> {
        let mut info = self.get_info();
        if Self::codemode(&context) {
            info.instructions = Some(tools::execute::INSTRUCTIONS.to_owned());
        }
        Ok(DiscoverResult::from_server_info(
            ProtocolVersion::KNOWN_VERSIONS.to_vec(),
            info,
        ))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let auth = Self::request_auth(&context)?.clone();
        let catalog = catalog(&self.app, &auth)
            .await
            .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
        let mut advertised = vec![tools::execute::definition().tool()];
        if !Self::codemode(&context) {
            for (integration, prefix) in [("git", ""), ("cog", "cog_")] {
                advertised.extend(
                    catalog
                        .native_tools(integration, prefix)
                        .await
                        .map_err(|error| ErrorData::internal_error(error.to_string(), None))?,
                );
            }
        }
        Ok(ListToolsResult::with_all_items(advertised))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let auth = Self::request_auth(&context)?.clone();
        let codemode = Self::codemode(&context);
        let arguments = request.arguments.unwrap_or_default();
        let args = Value::Object(arguments.clone());
        let resource = format!(
            "{}/.well-known/oauth-protected-resource",
            self.app.config.base_url.as_str().trim_end_matches('/')
        );

        if !codemode
            && let Some(tool) = tools::by_public_name(&request.name)
            && tool.id != NativeToolId::Execute
        {
            if !auth.allows(tool.required_scope) {
                return Ok(Self::scope_error(&[tool.required_scope.into()], &resource));
            }
            let catalog = catalog(&self.app, &auth)
                .await
                .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
            return Ok(match catalog.call(&tool.code_target(), args).await {
                Ok(value) => Self::success(value),
                Err(error) => Self::tool_error(error, &resource),
            });
        }
        if request.name != "execute" {
            return Err(ErrorData::method_not_found::<CallToolRequestMethod>());
        }
        let code = arguments
            .get("code")
            .and_then(Value::as_str)
            .ok_or_else(|| ErrorData::invalid_params("code is required", None))?
            .to_owned();
        let declared: HashSet<String> = arguments
            .get("integrations")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                ErrorData::invalid_params(
                    "integrations must be an array of immutable integration IDs",
                    None,
                )
            })?
            .iter()
            .map(|value| {
                value.as_str().map(str::to_owned).ok_or_else(|| {
                    ErrorData::invalid_params("integration IDs must be strings", None)
                })
            })
            .collect::<Result<_, _>>()?;
        let known: HashSet<String> = self
            .app
            .db
            .list_integrations(&auth.user)
            .map_err(|error| ErrorData::internal_error(error.to_string(), None))?
            .into_iter()
            .map(|integration| integration.id)
            .collect();
        if let Some(unknown) = declared.iter().find(|id| !known.contains(*id)) {
            return Ok(Self::corrective_error(format!(
                "unknown integration: {unknown}"
            )));
        }
        let missing: Vec<String> = declared
            .iter()
            .filter(|id| !auth.allows_integration(id))
            .map(|id| format!("integration:{id}"))
            .collect();
        if !missing.is_empty() {
            return Ok(Self::scope_error(&missing, &resource));
        }
        let mut runtime_catalog: Catalog = catalog(&self.app, &auth)
            .await
            .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
        runtime_catalog.retain_runtime_integrations(&declared);
        Ok(
            match tools::execute::invoke(self.app.runtime.clone(), Arc::new(runtime_catalog), code)
                .await
            {
                Ok(value) => Self::success(value),
                Err(error) => Self::tool_error(error, &resource),
            },
        )
    }
}
