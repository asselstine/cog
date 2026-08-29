use crate::{authz::InsufficientScope, upstream::Catalog};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    ffi::c_void,
    sync::{
        Arc, Mutex, Once,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

const MAX_CODE_BYTES: usize = 1024 * 1024;
const MAX_TOOL_CALLS: usize = 64;
const MAX_ARGUMENT_BYTES: usize = 256 * 1024;
const MAX_RESULT_BYTES: usize = 1024 * 1024;
const MAX_AGGREGATE_BYTES: usize = 4 * 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

static V8_INIT: Once = Once::new();
fn init() {
    V8_INIT.call_once(|| {
        let platform = v8::new_default_platform(0, false).make_shared();
        v8::V8::initialize_platform(platform);
        v8::V8::initialize();
    });
}

struct Host {
    catalog: Arc<Catalog>,
    handle: tokio::runtime::Handle,
    deadline: Instant,
    calls: AtomicUsize,
    aggregate_bytes: AtomicUsize,
    required_scopes: Mutex<BTreeSet<String>>,
}

struct HeapLimitState {
    exceeded: AtomicBool,
    handle: v8::IsolateHandle,
    original_limit: usize,
}

extern "C" fn near_heap_limit(
    data: *mut c_void,
    current_heap_limit: usize,
    _initial_heap_limit: usize,
) -> usize {
    let state = unsafe { &*(data as *const HeapLimitState) };
    state.exceeded.store(true, Ordering::Release);
    state.handle.terminate_execution();
    // V8 fatally aborts when a near-heap callback does not extend the limit.
    // Reserve enough headroom for the current allocation to unwind after the
    // uncatchable termination, matching celld's containment strategy.
    current_heap_limit
        .saturating_add(16 * 1024 * 1024)
        .max(state.original_limit.saturating_mul(2))
}

pub struct CodeRuntime {
    heap_bytes: usize,
    timeout: Duration,
}
impl CodeRuntime {
    pub fn new(heap_mb: usize, timeout: Duration) -> Self {
        init();
        Self {
            heap_bytes: heap_mb * 1024 * 1024,
            timeout,
        }
    }
    pub async fn execute(&self, code: String, catalog: Arc<Catalog>) -> anyhow::Result<Value> {
        anyhow::ensure!(code.len() <= MAX_CODE_BYTES, "code exceeds byte limit");
        reject_discarded_wrapper(&code)?;
        let heap = self.heap_bytes;
        let timeout = self.timeout;
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || run_v8(heap, timeout, &code, catalog, handle)).await?
    }
}

fn reject_discarded_wrapper(code: &str) -> anyhow::Result<()> {
    let trimmed = code.trim().trim_end_matches(';').trim();
    let async_wrapper = trimmed.starts_with("async ") || trimmed.starts_with("async(");
    let arrow_wrapper = trimmed.find("=>").is_some_and(|arrow| {
        let prefix = trimmed[..arrow].trim();
        !prefix.contains(';')
            && !prefix.starts_with("return ")
            && !prefix.starts_with("const ")
            && !prefix.starts_with("let ")
            && !prefix.starts_with("var ")
    });
    let function_wrapper = trimmed.starts_with("function")
        || trimmed.starts_with("(function")
        || trimmed.starts_with("(()")
        || trimmed.starts_with("(async")
        || async_wrapper
        || arrow_wrapper;
    anyhow::ensure!(
        !function_wrapper,
        "`code` is already a synchronous JavaScript function body; do not wrap it in {}function or arrow function. Write statements directly, do not use async/await, and return a value explicitly. Example: return {{matches: codemode.search('')}};",
        if async_wrapper { "an async " } else { "a " }
    );
    Ok(())
}

fn run_v8(
    heap: usize,
    timeout: Duration,
    code: &str,
    catalog: Arc<Catalog>,
    handle: tokio::runtime::Handle,
) -> anyhow::Result<Value> {
    let mut isolate = v8::Isolate::new(v8::CreateParams::default().heap_limits(0, heap));
    let terminator = isolate.thread_safe_handle();
    let heap_limit = isolate.get_heap_statistics().heap_size_limit();
    let heap_state = Box::new(HeapLimitState {
        exceeded: AtomicBool::new(false),
        handle: terminator.clone(),
        original_limit: heap_limit,
    });
    let heap_state_ptr = std::ptr::from_ref(heap_state.as_ref())
        .cast_mut()
        .cast::<c_void>();
    isolate.add_near_heap_limit_callback(near_heap_limit, heap_state_ptr);
    let finished = Arc::new(AtomicBool::new(false));
    let watcher_finished = finished.clone();
    let watchdog = std::thread::spawn(move || {
        std::thread::park_timeout(timeout);
        if !watcher_finished.load(Ordering::Acquire) {
            terminator.terminate_execution();
        }
    });
    let host = Box::new(Host {
        catalog,
        handle,
        deadline: Instant::now() + timeout,
        calls: AtomicUsize::new(0),
        aggregate_bytes: AtomicUsize::new(0),
        required_scopes: Mutex::new(BTreeSet::new()),
    });
    let host_ptr = Box::into_raw(host) as *mut c_void;
    let result = (|| {
        v8::scope!(let scope,&mut isolate);
        let data = v8::External::new(scope, host_ptr);
        let tmpl = v8::FunctionTemplate::builder(host_call)
            .data(data.into())
            .build(scope);
        let context = v8::Context::new(scope, v8::ContextOptions::default());
        let scope = &mut v8::ContextScope::new(scope, context);
        let global = context.global(scope);
        let function = tmpl
            .get_function(scope)
            .ok_or_else(|| anyhow::anyhow!("V8 function creation failed"))?;
        let key = v8::String::new(scope, "__cog_call").unwrap();
        global.set(scope, key.into(), function.into());
        let bootstrap = r#"globalThis.codemode=Object.freeze({search:(q='')=>__cog_call('search',String(q),'null'),describe:(t)=>__cog_call('describe',String(t),'null'),call:(t,args={})=>__cog_call('call',String(t),JSON.stringify(args))});"#;
        eval(scope, bootstrap)?;
        let source = format!(
            "const __result=(()=>{{{code}}})();if(__result&&typeof __result.then==='function')throw new Error(\"Promises are not supported; `code` must be synchronous. Remove async/await and return the direct result, for example: return {{matches: codemode.search('')}};\");JSON.stringify(__result)"
        );
        let text = {
            let try_catch = std::pin::pin!(v8::TryCatch::new(scope));
            let try_catch = try_catch.init();
            let src = v8::String::new(&try_catch, &source)
                .ok_or_else(|| anyhow::anyhow!("source too large"))?;
            let Some(script) = v8::Script::compile(&try_catch, src, None) else {
                let message = try_catch
                    .exception()
                    .and_then(|exception| exception.to_string(&try_catch))
                    .map(|message| message.to_rust_string_lossy(&try_catch))
                    .unwrap_or_else(|| "JavaScript compilation failed".into());
                return Err(anyhow::anyhow!(message));
            };
            let Some(value) = script.run(&try_catch) else {
                let message = try_catch
                    .exception()
                    .and_then(|exception| exception.to_string(&try_catch))
                    .map(|message| message.to_rust_string_lossy(&try_catch))
                    .unwrap_or_else(|| "JavaScript execution failed".into());
                return Err(anyhow::anyhow!(message));
            };
            value.to_rust_string_lossy(&try_catch)
        };
        anyhow::ensure!(
            text.len() <= MAX_OUTPUT_BYTES,
            "execution output exceeds byte limit"
        );
        if text == "undefined" {
            anyhow::bail!(
                "execution returned undefined; include an explicit return statement. Example: return {{matches: codemode.search('')}}; Use `return null;` for intentional empty output"
            )
        } else {
            Ok(serde_json::from_str(&text)?)
        }
    })();
    let heap_exceeded = heap_state.exceeded.load(Ordering::Acquire);
    if isolate.is_execution_terminating() {
        isolate.cancel_terminate_execution();
    }
    isolate.remove_near_heap_limit_callback(near_heap_limit, heap_limit);
    let required_scopes = unsafe {
        (&*(host_ptr as *const Host))
            .required_scopes
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect::<Vec<_>>()
    };
    unsafe {
        drop(Box::from_raw(host_ptr as *mut Host));
    }
    finished.store(true, Ordering::Release);
    watchdog.thread().unpark();
    let _ = watchdog.join();
    if !required_scopes.is_empty() {
        Err(InsufficientScope {
            scopes: required_scopes,
        }
        .into())
    } else if heap_exceeded {
        Err(anyhow::anyhow!("V8 heap limit exceeded"))
    } else {
        result
    }
}

fn eval<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    source: &str,
) -> anyhow::Result<v8::Local<'s, v8::Value>> {
    let src = v8::String::new(scope, source).ok_or_else(|| anyhow::anyhow!("source too large"))?;
    let script = v8::Script::compile(scope, src, None)
        .ok_or_else(|| anyhow::anyhow!("JavaScript compilation failed"))?;
    script
        .run(scope)
        .ok_or_else(|| anyhow::anyhow!("JavaScript execution failed"))
}

fn host_call(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    mut rv: v8::ReturnValue,
) {
    let Ok(ext) = v8::Local::<v8::External>::try_from(args.data()) else {
        return;
    };
    let host = unsafe { &*(ext.value() as *const Host) };
    let op = args.get(0).to_rust_string_lossy(scope);
    let target = args.get(1).to_rust_string_lossy(scope);
    let json_args = args.get(2).to_rust_string_lossy(scope);
    let call = host.calls.fetch_add(1, Ordering::SeqCst) + 1;
    let result = if call > MAX_TOOL_CALLS {
        Err(anyhow::anyhow!("tool-call count limit exceeded"))
    } else if target.len().saturating_add(json_args.len()) > MAX_ARGUMENT_BYTES {
        Err(anyhow::anyhow!("tool-call arguments exceed byte limit"))
    } else {
        let remaining = host.deadline.saturating_duration_since(Instant::now());
        host.handle.block_on(async {
            tokio::time::timeout(remaining, async {
                match op.as_str() {
                    "search" => host.catalog.search(&target).await,
                    "describe" => host.catalog.describe(&target).await,
                    "call" => {
                        host.catalog
                            .call(&target, serde_json::from_str(&json_args)?)
                            .await
                    }
                    _ => anyhow::bail!("unknown codemode operation"),
                }
            })
            .await
            .map_err(|_| anyhow::anyhow!("upstream call exceeded execution deadline"))?
        })
    };
    let encoded = match result.and_then(|v| Ok(serde_json::to_string(&v)?)) {
        Ok(v) if v.len() > MAX_RESULT_BYTES => {
            serde_json::to_string(&serde_json::json!({"error":"tool result exceeds byte limit"}))
                .unwrap()
        }
        Ok(v)
            if host
                .aggregate_bytes
                .fetch_add(v.len(), Ordering::SeqCst)
                .saturating_add(v.len())
                > MAX_AGGREGATE_BYTES =>
        {
            serde_json::to_string(
                &serde_json::json!({"error":"aggregate tool result limit exceeded"}),
            )
            .unwrap()
        }
        Ok(v) => v,
        Err(e) => {
            if let Some(required) = e.downcast_ref::<InsufficientScope>() {
                host.required_scopes
                    .lock()
                    .unwrap()
                    .extend(required.scopes.iter().cloned());
            }
            format!(
                "{{\"error\":{}}}",
                serde_json::to_string(&e.to_string()).unwrap()
            )
        }
    };
    if let Some(s) = v8::String::new(scope, &encoded)
        && let Some(v) = v8::json::parse(scope, s)
    {
        rv.set(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::{Tool, ToolProvider};
    use async_trait::async_trait;
    use serde_json::json;
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
                    "const p=new Proxy({},{get(){throw new Error('proxy trap')}}); return p.x"
                        .into(),
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
}
