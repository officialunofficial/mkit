//! Per-public-key name and replay records share one SQLite transaction.
use mkit_worker_common::replay::Ledger;
use serde::Deserialize;
use worker::{
    durable_object, wasm_bindgen, DurableObject, Env, Method, Request, Response, Result, State,
};

#[durable_object]
pub struct NameStore {
    ledger: Ledger,
    env: Env,
}
impl DurableObject for NameStore {
    fn new(state: State, env: Env) -> Self {
        Self {
            ledger: Ledger::new(state),
            env,
        }
    }
    async fn fetch(&self, mut req: Request) -> Result<Response> {
        self.ledger.initialize()?;
        self.ledger.state.storage().sql().exec("CREATE TABLE IF NOT EXISTS current_name (id INTEGER PRIMARY KEY CHECK(id = 1), record TEXT NOT NULL)", None)?;
        let path = req.path();
        let Some(pubkey) = path
            .strip_prefix("/name/")
            .map(str::to_ascii_lowercase)
            .filter(|p| super::is_pubkey_hex(p))
        else {
            return Response::error("invalid pubkey", 400);
        };
        match req.method() {
            Method::Put => super::set_name(&mut req, &self.env, &pubkey, &self.ledger).await,
            Method::Get => {
                #[derive(Deserialize)]
                struct Row {
                    record: String,
                }
                let rows: Vec<Row> = self
                    .ledger
                    .state
                    .storage()
                    .sql()
                    .exec("SELECT record FROM current_name WHERE id = 1", None)?
                    .to_array()?;
                if let Some(row) = rows.into_iter().next() {
                    return super::json_response(row.record);
                }
                Response::error("not found", 404)
            }
            _ => Response::error("method not allowed", 405),
        }
    }
}
