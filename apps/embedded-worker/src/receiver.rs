// SPDX-License-Identifier: MIT OR Apache-2.0
use serde::{Deserialize, Serialize};
use worker::{
    DurableObject, Env, Method, Request, Response, Result, State, durable_object, wasm_bindgen,
};

#[derive(Serialize, Deserialize)]
pub struct Delivery {
    pub reservation_id: String,
    pub kind: String,
    pub counter: Option<(u64, u64)>,
}
#[derive(Serialize, Deserialize)]
struct Counter {
    bytes: String,
    version: String,
}

/// Host state, reachable only through its DO binding, never a public route.
#[durable_object]
pub struct HostEvents {
    state: State,
}
impl DurableObject for HostEvents {
    fn new(state: State, _: Env) -> Self {
        Self { state }
    }
    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let sql = self.state.storage().sql();
        sql.exec("CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, kind TEXT, bytes TEXT, version TEXT)", None)?;
        sql.exec("CREATE TABLE IF NOT EXISTS counter (singleton INTEGER PRIMARY KEY, bytes TEXT NOT NULL, version TEXT NOT NULL)", None)?;
        // One INSERT commits the dedup key and the projection atomically.
        // Fixed-width decimal TEXT preserves all u64 bits across JS/SQLite and sorts by version.
        sql.exec("CREATE TRIGGER IF NOT EXISTS project_counter AFTER INSERT ON events WHEN NEW.version IS NOT NULL BEGIN INSERT INTO counter VALUES (1, NEW.bytes, NEW.version) ON CONFLICT(singleton) DO UPDATE SET bytes=excluded.bytes, version=excluded.version WHERE excluded.version > counter.version; END", None)?;
        if req.method() == Method::Get {
            let rows: Vec<Counter> = sql
                .exec("SELECT bytes, version FROM counter", None)?
                .to_array()?;
            return Response::from_json(&rows);
        }
        if req.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }
        // Only the trusted sink constructs these bounded metadata messages.
        // Parse text in Rust: Request::json first passes u64 through JS Number.
        let delivery: Delivery = serde_json::from_str(&req.text().await?)?;
        let (bytes, version) = delivery.counter.map_or((None, None), |(b, v)| {
            (Some(format!("{b:020}")), Some(format!("{v:020}")))
        });
        let inserted = sql
            .exec(
                "INSERT OR IGNORE INTO events VALUES (?, ?, ?, ?)",
                Some(vec![
                    delivery.reservation_id.clone().into(),
                    delivery.kind.into(),
                    bytes.into(),
                    version.into(),
                ]),
            )?
            .rows_written()
            != 0;
        worker::console_log!(
            "REFERENCE receiver {} {}",
            if inserted { "stored" } else { "duplicate" },
            delivery.reservation_id
        );
        Response::ok("acknowledged")
    }
}
