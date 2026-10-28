//! Small shared helpers.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Seconds since the Unix epoch, saturating at zero for pre-epoch clocks.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// Current UTC time as an RFC 3339 string, as required by `server-time`.
pub fn now_iso8601() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// Format a Unix timestamp as an RFC 3339 string.
pub fn iso8601(unix_seconds: u64) -> String {
    let Ok(seconds) = i64::try_from(unix_seconds) else {
        return String::new();
    };
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .ok()
        .and_then(|time| {
            time.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

/// Match an IRC host mask (`*` and `?` wildcards) against `text`.
///
/// Uses the linear-time greedy algorithm with backtracking to the last star,
/// so hostile masks cannot trigger exponential behaviour.
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut resume = 0usize;

    while ti < text.len() {
        if pi < pattern.len()
            && (pattern[pi] == b'?' || pattern[pi].eq_ignore_ascii_case(&text[ti]))
        {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star = Some(pi);
            pi += 1;
            resume = ti;
        } else if let Some(star_index) = star {
            pi = star_index + 1;
            resume += 1;
            ti = resume;
        } else {
            return false;
        }
    }
    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }
    pi == pattern.len()
}

/// Resolve an address to a hostname using the platform resolver.
///
/// Runs on a blocking thread because `getnameinfo` is synchronous. Platforms
/// without a binding simply fall back to the numeric address, which is what
/// callers already do when this returns `None`.
pub async fn reverse_lookup(address: IpAddr) -> Option<String> {
    #[cfg(unix)]
    {
        tokio::task::spawn_blocking(move || {
            let sockaddr = socket2::SockAddr::from(std::net::SocketAddr::new(address, 0));
            let mut host = [0 as libc::c_char; 1025];
            // Safety: `sockaddr` and `host` are valid for the whole call and
            // the length arguments match their buffers.
            let result = unsafe {
                libc::getnameinfo(
                    sockaddr.as_ptr(),
                    sockaddr.len(),
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            };
            if result != 0 {
                return None;
            }
            // Safety: `getnameinfo` succeeded, so the buffer holds a
            // NUL-terminated hostname.
            let name = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) };
            name.to_str().ok().map(str::to_owned)
        })
        .await
        .ok()
        .flatten()
    }

    #[cfg(not(unix))]
    {
        let _ = address;
        None
    }
}

/// SHA-256 digest of `input`, lowercase hex encoded.
pub fn sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Compare two hex digests without leaking their contents through timing.
pub fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    left.len() == right.len() && left.ct_eq(right).into()
}

/// Verify a plaintext password against a stored SHA-256 hex hash.
pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    constant_time_eq(
        &sha256_hex(password.as_bytes()),
        &stored_hash.to_ascii_lowercase(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_matching() {
        assert!(wildcard_match("*!*@*", "nick!user@host"));
        assert!(wildcard_match("nick!*@example.com", "nick!u@example.com"));
        assert!(!wildcard_match("nick!*@example.com", "other!u@example.com"));
        assert!(wildcard_match("a?c", "abc"));
        assert!(!wildcard_match("a?c", "ac"));
        assert!(wildcard_match("*", ""));
        assert!(wildcard_match("*a*b", "xxaxxb"));
        assert!(!wildcard_match("*a*b", "xxaxxc"));
    }

    #[test]
    fn wildcard_is_linear_on_adversarial_input() {
        let pattern = "*a*a*a*a*a*a*a*b";
        let text = "a".repeat(10_000);
        let start = std::time::Instant::now();
        assert!(!wildcard_match(pattern, &text));
        assert!(start.elapsed().as_millis() < 100);
    }

    #[test]
    fn password_hashing_round_trips() {
        let hash = sha256_hex(b"hunter2");
        assert_eq!(
            hash,
            "f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7"
        );
        assert!(verify_password("hunter2", &hash));
        assert!(!verify_password("hunter3", &hash));
    }

    #[test]
    fn iso8601_round_trip() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert!(!now_iso8601().is_empty());
    }
}
