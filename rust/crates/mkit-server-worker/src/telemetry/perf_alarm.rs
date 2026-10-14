//! Numeric, optional metadata supplied by the runtime to an alarm callback.

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeAlarmInfo {
    pub retry_count: Option<u32>,
    pub is_retry: Option<bool>,
}

impl RuntimeAlarmInfo {
    pub(crate) fn confirmed_schedule(&self, remembered: Option<u64>) -> Option<u64> {
        let retry = self.is_retry == Some(true) || self.retry_count.is_some_and(|count| count > 0);
        let initial = self.is_retry == Some(false) || self.retry_count == Some(0);
        if initial && !retry { remembered } else { None }
    }

    fn from_fields(retry_count: Option<f64>, is_retry: Option<bool>) -> Self {
        let retry_count = retry_count
            .filter(|n| n.is_finite() && *n >= 0.0 && n.fract() == 0.0 && *n <= f64::from(u32::MAX))
            .map(|n| {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                {
                    n as u32
                }
            });
        Self {
            retry_count,
            is_retry,
        }
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn from_js(info: &worker::wasm_bindgen::JsValue) -> Self {
        use worker::{js_sys::Reflect, wasm_bindgen::JsValue};
        // Undefined (including an argument-free call), null and invalid fields
        // remain absent. Never retain the runtime object or exception text.
        let count = Reflect::get(info, &JsValue::from_str("retryCount"))
            .ok()
            .and_then(|value| value.as_f64());
        let retry = Reflect::get(info, &JsValue::from_str("isRetry"))
            .ok()
            .and_then(|value| value.as_bool());
        Self::from_fields(count, retry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remembered_arm_is_not_misreported_as_a_runtime_retry_schedule() {
        for (count, retry, expected) in [
            (None, None, None),
            (Some(0.0), Some(false), Some(100)),
            (Some(1.0), Some(true), None),
            (Some(1.0), Some(false), None),
        ] {
            let runtime = RuntimeAlarmInfo::from_fields(count, retry);
            assert_eq!(runtime.confirmed_schedule(Some(100)), expected);
            assert_eq!(runtime.confirmed_schedule(None), None);
        }
    }

    #[test]
    fn absent_and_invalid_runtime_alarm_metadata_stays_unknown() {
        assert_eq!(
            RuntimeAlarmInfo::from_fields(None, None),
            RuntimeAlarmInfo::default()
        );
        for invalid in [
            f64::NAN,
            f64::INFINITY,
            -1.0,
            0.5,
            f64::from(u32::MAX) + 1.0,
        ] {
            assert_eq!(
                RuntimeAlarmInfo::from_fields(Some(invalid), None),
                RuntimeAlarmInfo::default()
            );
        }
        assert_eq!(
            RuntimeAlarmInfo::from_fields(Some(0.0), Some(false)),
            RuntimeAlarmInfo {
                retry_count: Some(0),
                is_retry: Some(false),
            }
        );
        assert_eq!(
            RuntimeAlarmInfo::from_fields(Some(6.0), Some(true)),
            RuntimeAlarmInfo {
                retry_count: Some(6),
                is_retry: Some(true),
            }
        );
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn javascript_undefined_and_invalid_alarm_info_stays_unknown() {
        use worker::{
            js_sys::{Object, Reflect},
            wasm_bindgen::JsValue,
        };
        for absent in [JsValue::UNDEFINED, JsValue::NULL, JsValue::from_f64(1.0)] {
            assert_eq!(
                RuntimeAlarmInfo::from_js(&absent),
                RuntimeAlarmInfo::default()
            );
        }
        let invalid = Object::new();
        Reflect::set(&invalid, &"retryCount".into(), &"invalid".into()).expect("set test metadata");
        Reflect::set(&invalid, &"isRetry".into(), &"invalid".into()).expect("set test metadata");
        assert_eq!(
            RuntimeAlarmInfo::from_js(invalid.as_ref()),
            RuntimeAlarmInfo::default()
        );
    }
}
