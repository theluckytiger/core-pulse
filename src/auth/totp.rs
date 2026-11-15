//! Time-based one-time passwords (RFC 6238): 6 digits, 30 second steps and
//! HMAC-SHA1, which is what authenticator apps expect.

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

const STEP: i64 = 30;
const DIGITS: u32 = 6;

/// The code for one time step.
fn code(secret: &[u8], step: u64) -> Option<u32> {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).ok()?;
    mac.update(&step.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let offset = usize::from(hash[19] & 0x0f);
    let value = u32::from_be_bytes([
        hash[offset] & 0x7f,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);
    Some(value % 10u32.pow(DIGITS))
}

/// Checks a code, allowing one step of clock drift either way. Returns the
/// matching step. The caller stores it, and steps up to `last_used` are
/// refused, so a code works only once.
pub fn verify(secret: &[u8], input: &str, now: i64, last_used: Option<u64>) -> Option<u64> {
    let input = input.trim();
    if input.len() != DIGITS as usize || !input.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let wanted: u32 = input.parse().ok()?;
    let current = u64::try_from(now / STEP).ok()?;

    [current.saturating_sub(1), current, current + 1]
        .into_iter()
        .filter(|step| last_used.is_none_or(|last| *step > last))
        .find(|step| code(secret, *step) == Some(wanted))
}

/// The code an authenticator app shows at `now`.
#[cfg(test)]
pub fn code_at(secret: &[u8], now: i64) -> String {
    format!(
        "{:06}",
        code(secret, (now / STEP) as u64).unwrap_or_default()
    )
}

/// otpauth:// link for authenticator apps. `account` must be URL-safe.
pub fn provisioning_uri(secret_base32: &str, account: &str) -> String {
    format!(
        "otpauth://totp/core-pulse:{account}?secret={secret_base32}&issuer=core-pulse&algorithm=SHA1&digits={DIGITS}&period={STEP}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 appendix B, SHA-1 key; the last six digits of each code.
    const KEY: &[u8] = b"12345678901234567890";
    const VECTORS: [(i64, &str); 6] = [
        (59, "287082"),
        (1_111_111_109, "081804"),
        (1_111_111_111, "050471"),
        (1_234_567_890, "005924"),
        (2_000_000_000, "279037"),
        (20_000_000_000, "353130"),
    ];

    #[test]
    fn matches_the_rfc_test_vectors() {
        for (time, expected) in VECTORS {
            let step = (time / STEP) as u64;
            assert_eq!(
                format!("{:06}", code(KEY, step).unwrap()),
                expected,
                "t={time}"
            );
            assert_eq!(verify(KEY, expected, time, None), Some(step), "t={time}");
        }
    }

    #[test]
    fn accepts_one_step_of_drift() {
        let (time, code) = VECTORS[3];
        assert!(verify(KEY, code, time + STEP, None).is_some());
        assert!(verify(KEY, code, time - STEP, None).is_some());
        assert!(verify(KEY, code, time + 3 * STEP, None).is_none());
    }

    #[test]
    fn refuses_a_code_twice() {
        let (time, code) = VECTORS[3];
        let step = verify(KEY, code, time, None).unwrap();
        assert_eq!(verify(KEY, code, time, Some(step)), None);
    }

    #[test]
    fn refuses_malformed_input() {
        let (time, _) = VECTORS[3];
        for input in ["", "12345", "1234567", "12a456", "-12345"] {
            assert_eq!(verify(KEY, input, time, None), None, "{input}");
        }
        assert!(verify(KEY, " 005924 ", time, None).is_some());
    }

    #[test]
    fn builds_the_provisioning_uri() {
        let uri = provisioning_uri("JBSWY3DPEHPK3PXP", "admin");
        assert!(uri.starts_with("otpauth://totp/core-pulse:admin?secret=JBSWY3DPEHPK3PXP&"));
        assert!(uri.contains("digits=6") && uri.contains("period=30"));
    }
}
