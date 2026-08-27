use crate::git::model::GitOperation;
pub fn permits(permission: &str, operation: GitOperation) -> bool {
    permission == "write" || (permission == "read" && operation == GitOperation::Read)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn write_implies_read() {
        assert!(permits("write", GitOperation::Read));
        assert!(!permits("read", GitOperation::Write));
    }
}
