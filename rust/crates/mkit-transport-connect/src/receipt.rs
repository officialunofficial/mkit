//! Bounded payment receipt values from successful unary writes.
use http::HeaderMap;
use std::sync::Arc;

pub(crate) type ReceiptObserver = Arc<dyn Fn(&AdmissionReceipt) + Send + Sync>;

/// Receipt value; formatting reveals only its byte length.
#[derive(Clone)]
pub struct ReceiptValue(String);

impl ReceiptValue {
    /// Access the opaque value without formatting or logging it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ReceiptValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReceiptValue(len={})", self.0.len())
    }
}

impl std::fmt::Display for ReceiptValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{} bytes]", self.0.len())
    }
}

/// One receipt header returned by a successful write.
#[derive(Debug, Clone)]
pub struct AdmissionReceipt {
    /// Connect procedure path.
    pub procedure: &'static str,
    /// Lowercase header name.
    pub header: &'static str,
    /// Opaque receipt value.
    pub value: ReceiptValue,
}

pub(crate) fn observe_receipts(
    headers: &HeaderMap,
    procedure: &'static str,
    observer: &Option<ReceiptObserver>,
) {
    let Some(observer) = observer else { return };
    for name in ["payment-receipt", "payment-response"] {
        let mut accepted = 0;
        for value in headers.get_all(name) {
            let bytes = value.as_bytes();
            if bytes.len() > 8_192 {
                continue;
            }
            // Headers are opaque on receipt ingress; retain only valid UTF-8.
            if let Ok(value) = std::str::from_utf8(bytes) {
                if accepted == 8 {
                    break;
                }
                observer(&AdmissionReceipt {
                    procedure,
                    header: name,
                    value: ReceiptValue(value.to_owned()),
                });
                accepted += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn oversized_values_do_not_consume_receipt_limit() {
        let mut headers = HeaderMap::new();
        for _ in 0..8 {
            headers.append("payment-receipt", "x".repeat(8_193).parse().unwrap());
        }
        headers.append("payment-receipt", "valid".parse().unwrap());
        let received = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&received);
        let observer: Option<ReceiptObserver> = Some(Arc::new(move |receipt| {
            captured
                .lock()
                .unwrap()
                .push(receipt.value.as_str().to_owned())
        }));
        observe_receipts(&headers, "UpdateRef", &observer);
        assert_eq!(*received.lock().unwrap(), ["valid"]);
    }
}
