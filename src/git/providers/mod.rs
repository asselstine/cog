use crate::git::model::*;
use async_trait::async_trait;
pub mod github;

#[async_trait]
pub trait GitProvider: Send + Sync {
    async fn resolve_repository(
        &self,
        reference: &RepositoryReference,
    ) -> anyhow::Result<ResolvedRepository>;
    async fn authorize_upstream(
        &self,
        repository: &ResolvedRepository,
        operation: GitOperation,
    ) -> anyhow::Result<UpstreamAuthorization>;
    fn upstream_url(&self, repository: &ResolvedRepository) -> anyhow::Result<url::Url>;
}
