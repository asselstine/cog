use crate::git::model::GitOperation;
pub fn permits(permission: &str, operation: GitOperation) -> bool {
    permission == "write" || (permission == "read" && operation == GitOperation::Read)
}
