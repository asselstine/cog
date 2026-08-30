use crate::mcp::{Tool, ToolAnnotations};
use serde_json::Value;
use std::sync::Arc;

pub mod admin;
pub mod execute;
pub mod git;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NativeToolId {
    Execute,
    IntegrationsList,
    IntegrationGet,
    GitHubAppSetupStart,
    GitHubAppSetupStatus,
    IntegrationCreate,
    IntegrationUpdate,
    IntegrationSetEnabled,
    IntegrationAuthorize,
    IntegrationReconnect,
    IntegrationDisconnect,
    IntegrationDelete,
    AgentsList,
    AgentGetSelf,
    AgentUpdateSelf,
    AgentRevoke,
    TokensList,
    TokenRevoke,
    IdentityGrantRevoke,
    AuditList,
    RepositoryAccess,
    SshKeyStatus,
    SshKeyRegister,
    SshKeyLeaseRenew,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeNamespace {
    Execute,
    Cog,
    Git,
}

impl NativeNamespace {
    pub const fn code_name(self) -> &'static str {
        match self {
            Self::Execute => "",
            Self::Cog => "cog",
            Self::Git => "git",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeAvailability {
    Always,
    Ssh,
}

#[derive(Debug, Clone)]
pub struct NativeToolDefinition {
    pub id: NativeToolId,
    pub namespace: NativeNamespace,
    pub wire_name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
    pub annotations: ToolAnnotations,
    pub required_scope: &'static str,
    pub availability: NativeAvailability,
}

impl NativeToolDefinition {
    pub fn tool(&self) -> Tool {
        let input_schema = self
            .input_schema
            .as_object()
            .cloned()
            .expect("native tool input schema is an object");
        Tool::new(self.wire_name, self.description, Arc::new(input_schema))
            .with_title(self.title)
            .with_annotations(self.annotations.clone())
            .with_meta(crate::mcp::model::native_tool_meta(self.required_scope))
    }

    pub fn code_target(&self) -> String {
        match self.namespace {
            NativeNamespace::Execute => self.wire_name.into(),
            namespace => format!("{}.{}", namespace.code_name(), self.wire_name),
        }
    }

    pub fn public_name(&self) -> String {
        match self.namespace {
            NativeNamespace::Execute | NativeNamespace::Git => self.wire_name.into(),
            NativeNamespace::Cog => format!("cog_{}", self.wire_name),
        }
    }

    pub fn available(&self, ssh_available: bool) -> bool {
        matches!(self.availability, NativeAvailability::Always) || ssh_available
    }
}

pub fn definitions() -> Vec<NativeToolDefinition> {
    let mut definitions = vec![execute::definition()];
    definitions.extend(admin::definitions());
    definitions.extend(git::definitions());
    definitions
}

pub fn by_id(id: NativeToolId) -> NativeToolDefinition {
    definitions()
        .into_iter()
        .find(|definition| definition.id == id)
        .expect("every native tool ID has one definition")
}

pub fn by_code_target(target: &str) -> Option<NativeToolDefinition> {
    definitions()
        .into_iter()
        .find(|definition| definition.code_target() == target)
}

pub fn by_public_name(name: &str) -> Option<NativeToolDefinition> {
    definitions()
        .into_iter()
        .find(|definition| definition.public_name() == name)
}

pub fn annotations(
    required_scope: &'static str,
    read_only: bool,
    destructive: bool,
    idempotent: bool,
    open_world: bool,
) -> ToolAnnotations {
    let _ = required_scope;
    ToolAnnotations::new()
        .read_only(read_only)
        .destructive(destructive)
        .idempotent(idempotent)
        .open_world(open_world)
}
