use cog::git::GitOperation;
use cog::git::grants::*;
#[test]
fn write_implies_read() {
    assert!(permits("write", GitOperation::Read));
    assert!(!permits("read", GitOperation::Write));
}
