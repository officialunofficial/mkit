// SPDX-License-Identifier: MIT OR Apache-2.0
//! Durable nonce ledger. Every check and effect runs in one explicit SQLite
//! transaction. Object publication reserves the same ledger entry before R2;
//! identical retries may finish the immutable put without a second quota charge.
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, rc::Rc};
use worker::{
    Error, Response, Result, State, js_sys,
    wasm_bindgen::{JsCast, JsValue, closure::Closure},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    pub scope: String,
    pub author: String,
    pub fingerprint: String,
    pub expires_at: i64,
}
impl From<&mkit_core::write_auth::Authorized> for Proof {
    fn from(auth: &mkit_core::write_auth::Authorized) -> Self {
        Self {
            scope: auth.scope.clone(),
            author: auth.public_key.clone(),
            fingerprint: auth.fingerprint.clone(),
            expires_at: auth.expires_at,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reply {
    pub status: u16,
    pub body: String,
}
impl Reply {
    pub fn json<T: Serialize>(value: &T) -> Result<Self> {
        Ok(Self {
            status: 200,
            body: serde_json::to_string(value).map_err(|e| Error::RustError(e.to_string()))?,
        })
    }
    pub fn error(message: impl Into<String>, status: u16) -> Result<Self> {
        Ok(Self {
            status,
            body: message.into(),
        })
    }
    pub fn response(self) -> Result<Response> {
        let mut response = Response::ok(self.body)?.with_status(self.status);
        response
            .headers_mut()
            .set("Content-Type", "application/json")?;
        Ok(response)
    }
}

#[derive(Clone)]
pub struct Ledger {
    pub state: Rc<State>,
    storage: std::result::Result<JsValue, JsValue>,
}
impl Ledger {
    pub fn new(state: State) -> Self {
        let raw = state._inner();
        let storage = raw.storage().map(JsValue::from);
        Self {
            state: Rc::new(State::from(raw)),
            storage,
        }
    }
    pub fn initialize(&self) -> Result<()> {
        self.state.storage().sql().exec("CREATE TABLE IF NOT EXISTS authenticated_operations (scope TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, expires INTEGER NOT NULL, reply TEXT);", None)?;
        self.state.storage().sql().exec("CREATE INDEX IF NOT EXISTS authenticated_operations_expires ON authenticated_operations(expires);", None)?;
        Ok(())
    }
    /// Errors thrown by the callback roll back nonce, quota, and effects together.
    pub fn transaction<T: 'static>(
        &self,
        action: impl FnOnce() -> Result<T> + 'static,
    ) -> Result<T> {
        let storage = self.storage.as_ref().map_err(|e| Error::from(e.clone()))?;
        let output = Rc::new(RefCell::new(None));
        let saved = output.clone();
        let mut action = Some(action);
        let callback = Closure::wrap(Box::new(move || -> std::result::Result<JsValue, JsValue> {
            let result = action.take().expect("transaction callback called once")();
            let failed = result.is_err();
            *saved.borrow_mut() = Some(result);
            if failed {
                Err(JsValue::from_str("authenticated transaction failed"))
            } else {
                Ok(JsValue::UNDEFINED)
            }
        })
            as Box<dyn FnMut() -> std::result::Result<JsValue, JsValue>>);
        let function = js_sys::Reflect::get(storage, &JsValue::from_str("transactionSync"))?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| Error::RustError("transactionSync is unavailable".into()))?;
        let result = function.call1(storage, callback.as_ref());
        let value = output.borrow_mut().take();
        if let Some(value) = value {
            match value {
                Err(error) => Err(error),
                Ok(value) => result.map(|_| value).map_err(Error::from),
            }
        } else {
            Err(Error::RustError("transaction callback did not run".into()))
        }
    }
    /// None: new reservation; Some(None): interrupted immutable publication;
    /// Some(Some(reply)): completed operation. Must run within transaction().
    pub fn reserve(&self, proof: &Proof, now: i64) -> Result<Option<Option<Reply>>> {
        if now > proof.expires_at {
            return Err(Error::RustError("signed operation expired".into()));
        }
        #[derive(Deserialize)]
        struct Row {
            fingerprint: String,
            reply: Option<String>,
        }
        let rows: Vec<Row> = self
            .state
            .storage()
            .sql()
            .exec(
                "SELECT fingerprint, reply FROM authenticated_operations WHERE scope = ?",
                vec![proof.scope.clone().into()],
            )?
            .to_array()?;
        if let Some(row) = rows.into_iter().next() {
            if row.fingerprint != proof.fingerprint {
                return Err(Error::RustError(
                    "nonce reused for a different operation".into(),
                ));
            }
            let reply = row
                .reply
                .map(|json| {
                    serde_json::from_str(&json).map_err(|e| Error::RustError(e.to_string()))
                })
                .transpose()?;
            return Ok(Some(reply));
        }
        self.state.storage().sql().exec(
            "DELETE FROM authenticated_operations WHERE expires < ?",
            vec![now.into()],
        )?;
        self.state.storage().sql().exec(
            "INSERT INTO authenticated_operations (scope, fingerprint, expires) VALUES (?, ?, ?)",
            vec![
                proof.scope.clone().into(),
                proof.fingerprint.clone().into(),
                proof.expires_at.into(),
            ],
        )?;
        Ok(None)
    }
    pub fn finish(&self, proof: &Proof, reply: &Reply) -> Result<()> {
        let json = serde_json::to_string(reply).map_err(|e| Error::RustError(e.to_string()))?;
        self.state.storage().sql().exec(
            "UPDATE authenticated_operations SET reply = ? WHERE scope = ? AND fingerprint = ?",
            vec![
                json.into(),
                proof.scope.clone().into(),
                proof.fingerprint.clone().into(),
            ],
        )?;
        Ok(())
    }
}
