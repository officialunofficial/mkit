//! Local transport contract fixture; never linked by the production Worker.
use mkit_server_worker::naming::DoTarget;
use mkit_server_worker::ns_client::{NsTransport, StubTransport};
use worker::{Context, Env, Request, Response, Result, event};

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let mode = req.path();
    let op = match mode.as_str() {
        "/success" => "success",
        "/error_status" => "error_status",
        "/error_body" => "error_body",
        "/abort_header" => "abort_header",
        "/abort_body" => "abort_body",
        "/batch_nested" => "batch_nested",
        "/batch_error" => "batch_error",
        "/batch_scanner" => "batch_scanner",
        _ => return Response::error("fixture route absent", 404),
    };
    let transport = StubTransport::new(env, Default::default());
    let target = DoTarget {
        binding: "REFSTORE",
        name: mode.clone(),
    };
    if op.starts_with("batch_") {
        let width = if op == "batch_scanner" { 6 } else { 4 };
        let replies = futures::future::join_all((0..width).map(|n| {
            let transport = &transport;
            async move {
                let target = DoTarget {
                    binding: "REFSTORE",
                    name: format!("{op}/{n}"),
                };
                let method = if op == "batch_error" && n == 0 {
                    "error_status"
                } else {
                    "success"
                };
                transport.call(&target, method, "first".into()).await
            }
        }))
        .await;
        let outcome = if replies.iter().any(std::result::Result::is_err) {
            "unavailable"
        } else {
            transport
                .call(&target, "success", "nested".into())
                .await
                .map_err(|_| worker::Error::RustError("fixture nested failed".into()))?;
            "joined+nested"
        };
        return Response::from_json(
            &serde_json::json!({"mode":op,"outcome":outcome,"width":width}),
        );
    }
    let call = Box::pin(transport.call(&target, op, "{}".into()));
    let at = worker::Date::now().as_millis();
    let outcome = if op.starts_with("abort_") {
        let timer = Box::pin(worker::Delay::from(std::time::Duration::from_millis(50)));
        match futures::future::select(call, timer).await {
            futures::future::Either::Left((result, _)) => {
                format!("unexpected completion: {result:?}")
            }
            futures::future::Either::Right(((), pending)) => {
                drop(pending);
                // This delay observes the JS transport after Rust future drop.
                worker::Delay::from(std::time::Duration::from_millis(50)).await;
                "dropped".into()
            }
        }
    } else {
        match call.await {
            Ok(body) => format!("ok:{body}"),
            Err(_) => "unavailable".into(),
        }
    };
    Response::from_json(&serde_json::json!({"mode":op,"outcome":outcome,
        "elapsed_ms":worker::Date::now().as_millis()-at}))
}
