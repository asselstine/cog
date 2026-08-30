use async_trait::async_trait;
use cog::mcp::{Catalog, Tool, ToolProvider};
use cog::runtime::*;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
#[tokio::test(flavor = "multi_thread")]
async fn javascript() {
    let r = CodeRuntime::new(16, Duration::from_secs(2));
    let out = r
        .execute(
            "return [1,2,3].map(x=>x*2);".into(),
            Arc::new(Catalog::new()),
        )
        .await
        .unwrap();
    assert_eq!(out, serde_json::json!([2, 4, 6]));
}
#[tokio::test(flavor = "multi_thread")]
async fn terminates_infinite_loop() {
    let r = CodeRuntime::new(16, Duration::from_millis(20));
    assert!(
        r.execute("for(;;){}".into(), Arc::new(Catalog::new()))
            .await
            .is_err()
    );
}
struct Fake;
#[async_trait]
impl ToolProvider for Fake {
    async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
        Ok(vec![Tool {
            name: "add".into(),
            title: None,
            description: None,
            input_schema: json!({}),
            extra: serde_json::Map::new(),
        }])
    }
    async fn call(&self, name: &str, args: Value) -> anyhow::Result<Value> {
        anyhow::ensure!(name == "add", "unknown tool");
        Ok(json!(
            args["a"].as_i64().unwrap() + args["b"].as_i64().unwrap()
        ))
    }
}
struct Big;
#[async_trait]
impl ToolProvider for Big {
    async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
        Ok(Vec::new())
    }
    async fn call(&self, _name: &str, args: Value) -> anyhow::Result<Value> {
        Ok(Value::String(
            "x".repeat(args["size"].as_u64().unwrap() as usize),
        ))
    }
}
struct ScopeRequired;
#[async_trait]
impl ToolProvider for ScopeRequired {
    async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
        Ok(vec![Tool {
            name: "restricted".into(),
            title: None,
            description: None,
            input_schema: json!({}),
            extra: serde_json::Map::new(),
        }])
    }
    async fn call(&self, _name: &str, _args: Value) -> anyhow::Result<Value> {
        Err(crate::authz::InsufficientScope::one("integration:restricted").into())
    }
}
#[tokio::test(flavor = "multi_thread")]
async fn codemode_host_calls_and_errors() {
    let mut c = Catalog::new();
    c.add("math".into(), Arc::new(Fake));
    let r = CodeRuntime::new(16, Duration::from_secs(1));
    assert_eq!(
        r.execute(
            "return codemode.call('math.add',{a:2,b:3})".into(),
            Arc::new(c)
        )
        .await
        .unwrap(),
        5
    );
    assert!(
        r.execute("this is not javascript".into(), Arc::new(Catalog::new()))
            .await
            .is_err()
    );
    assert!(
        r.execute("return Promise.resolve(1)".into(), Arc::new(Catalog::new()))
            .await
            .is_err()
    );
    assert!(
        r.execute("x".repeat(MAX_CODE_BYTES + 1), Arc::new(Catalog::new()))
            .await
            .unwrap_err()
            .to_string()
            .contains("code exceeds")
    );
    let calls = "codemode.search('');".repeat(MAX_TOOL_CALLS + 1);
    let value = r
        .execute(
            format!("{calls} return codemode.search('')"),
            Arc::new(Catalog::new()),
        )
        .await
        .unwrap();
    assert_eq!(value["error"], "tool-call count limit exceeded");
    for code in ["return undefined", "const answer = 42"] {
        let error = r
            .execute(code.into(), Arc::new(Catalog::new()))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("explicit return"));
        assert!(error.len() < 512);
    }
    assert_eq!(
        r.execute("return null".into(), Arc::new(Catalog::new()))
            .await
            .unwrap(),
        Value::Null
    );
    for code in [
        "async () => { await codemode.search(''); }",
        "() => { return codemode.search(''); }",
        "function () { return null; }",
    ] {
        let error = r
            .execute(code.into(), Arc::new(Catalog::new()))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("already a synchronous JavaScript function body"));
        assert!(error.len() < 512);
    }
    let mut big = Catalog::new();
    big.add("big".into(), Arc::new(Big));
    let big = Arc::new(big);
    assert_eq!(
        r.execute("codemode.search(''); return null".into(), big.clone(),)
            .await
            .unwrap(),
        Value::Null
    );
    assert_eq!(
        r.execute(
            format!(
                "return codemode.call('big.make',{{text:'{}'}})",
                "x".repeat(MAX_ARGUMENT_BYTES)
            ),
            big.clone()
        )
        .await
        .unwrap()["error"],
        "tool-call arguments exceed byte limit"
    );
    assert_eq!(
        r.execute(
            format!(
                "return codemode.call('big.make',{{size:{}}})",
                MAX_RESULT_BYTES + 1
            ),
            big.clone()
        )
        .await
        .unwrap()["error"],
        "tool result exceeds byte limit"
    );
    let aggregate = format!(
        "{} return codemode.call('big.make',{{size:{}}})",
        format!(
            "codemode.call('big.make',{{size:{}}});",
            MAX_RESULT_BYTES - 3
        )
        .repeat(4),
        MAX_RESULT_BYTES - 3,
    );
    assert_eq!(
        r.execute(aggregate, big).await.unwrap()["error"],
        "aggregate tool result limit exceeded"
    );
    assert_eq!(
        r.execute(
            "return __cog_call('unknown','','null')".into(),
            Arc::new(Catalog::new()),
        )
        .await
        .unwrap()["error"],
        "unknown codemode operation"
    );

    let mut restricted = Catalog::new();
    restricted.add("scope".into(), Arc::new(ScopeRequired));
    let restricted = Arc::new(restricted);
    assert_eq!(
        r.execute(
            "codemode.search(''); return null".into(),
            restricted.clone(),
        )
        .await
        .unwrap(),
        Value::Null
    );
    let error = r
        .execute(
            "return codemode.call('scope.restricted',{})".into(),
            restricted,
        )
        .await
        .unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<crate::authz::InsufficientScope>()
            .unwrap()
            .scopes,
        ["integration:restricted"]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn documented_codemode_conventions_are_compatible() {
    let mut catalog = Catalog::new();
    catalog.add("math".into(), Arc::new(Fake));
    let runtime = CodeRuntime::new(16, Duration::from_secs(1));
    let value = runtime
        .execute(
            r#"
const matches=codemode.search('add');
const schema=codemode.describe('math.add');
const sum=codemode.call('math.add',{a:20,b:22});
return {matches,schema,sum,missing:codemode.call('math.missing',{})};
"#
            .into(),
            Arc::new(catalog),
        )
        .await
        .unwrap();
    assert_eq!(value["matches"][0]["integration"], "math");
    assert_eq!(value["matches"][0]["tool"], "add");
    assert!(value["schema"]["inputSchema"].is_object());
    assert_eq!(value["sum"], 42);
    assert!(value["missing"]["error"].is_string());
}

#[tokio::test(flavor = "multi_thread")]
async fn recursion_proxies_large_json_and_termination_races_are_contained() {
    let runtime = Arc::new(CodeRuntime::new(16, Duration::from_millis(50)));
    assert!(
        runtime
            .execute(
                "function f(){return f()} return f()".into(),
                Arc::new(Catalog::new())
            )
            .await
            .is_err()
    );
    assert!(
        runtime
            .execute(
                "const p=new Proxy({},{get(){throw new Error('proxy trap')}}); return p.x".into(),
                Arc::new(Catalog::new()),
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("proxy trap")
    );
    let oversized = format!("return '{}';", "x".repeat(MAX_OUTPUT_BYTES + 1));
    assert!(
        runtime
            .execute(oversized, Arc::new(Catalog::new()))
            .await
            .is_err()
    );

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let runtime = runtime.clone();
        tasks.push(tokio::spawn(async move {
            runtime
                .execute("for(;;){}".into(), Arc::new(Catalog::new()))
                .await
        }));
    }
    for task in tasks {
        assert!(task.await.unwrap().is_err());
    }
    assert_eq!(
        runtime
            .execute("return 7".into(), Arc::new(Catalog::new()))
            .await
            .unwrap(),
        7
    );
}

#[test]
fn heap_exhaustion_is_contained_in_isolate() {
    if std::env::var_os("COG_HEAP_TEST_CHILD").is_some() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(CodeRuntime::new(8, Duration::from_secs(2)).execute(
            "const values=[];for(;;)values.push(new Array(100000).fill('xxxxxxxx'))".into(),
            Arc::new(Catalog::new()),
        ));
        assert!(result.is_err());
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("runtime::tests::heap_exhaustion_is_contained_in_isolate")
        .arg("--nocapture")
        .env("COG_HEAP_TEST_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "heap-limited isolate crashed process: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
