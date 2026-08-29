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

pub const MAX_CODE_BYTES: usize = 1024 * 1024;
pub const MAX_TOOL_CALLS: usize = 64;
pub const MAX_ARGUMENT_BYTES: usize = 256 * 1024;
pub const MAX_RESULT_BYTES: usize = 1024 * 1024;
pub const MAX_AGGREGATE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

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
