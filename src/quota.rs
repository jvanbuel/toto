//! The quota signal: what the provider's responses say about how much of the contributor's
//! allowance is left. The credential proxy reads it from every upstream response (it is the
//! only thing that sees them); the policy turns it into a pause so the contributor keeps the
//! share they reserved for themselves, and "donate unused capacity" has an input.
//!
//! Three header families are understood:
//! - Anthropic subscription (OAuth): `anthropic-ratelimit-unified-status` (`allowed`,
//!   `allowed_warning`, `rejected`), `-5h-utilization` / `-7d-utilization` (fraction of the
//!   window used), `-5h-reset` / `-7d-reset` / `-reset` (unix seconds);
//! - Anthropic API keys: `anthropic-ratelimit-{requests,tokens,input-tokens,output-tokens}-{limit,remaining,reset}`
//!   (reset as RFC 3339);
//! - OpenAI: `x-ratelimit-{limit,remaining,reset}-{requests,tokens}` (reset as a duration such
//!   as `6m0s`).
//!
//! Plus the two things every provider says the same way: a 429 or 529 status, and `retry-after`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuotaSignal {
    /// Unix seconds when the response arrived.
    pub seen_at: i64,
    pub status: u16,
    /// The provider refused for lack of allowance: 429, 529, or a unified status of `rejected`.
    pub limited: bool,
    /// Share of the busiest window already used, 0..1 (subscriptions report this).
    pub utilization: Option<f64>,
    /// Share of the tightest limit still available, 0..1 (API keys report this).
    pub remaining: Option<f64>,
    /// Unix seconds when the limiting window resets, as the provider states it.
    pub resets_at: Option<i64>,
    /// `retry-after` on a refusal, in seconds.
    pub retry_after: Option<u64>,
}

impl QuotaSignal {
    /// Reads the signal from an upstream response. `headers` are lower-cased names.
    pub fn from_response(status: u16, headers: &[(String, String)], now: i64) -> QuotaSignal {
        let h = |name: &str| headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.trim());
        let num = |name: &str| h(name).and_then(|v| v.parse::<f64>().ok());
        let mut s = QuotaSignal { seen_at: now, status, limited: matches!(status, 429 | 529), utilization: None, remaining: None, resets_at: None, retry_after: None };
        s.retry_after = h("retry-after").and_then(|v| v.parse::<u64>().ok());

        // Subscription windows.
        if h("anthropic-ratelimit-unified-status").is_some_and(|v| v.eq_ignore_ascii_case("rejected")) {
            s.limited = true;
        }
        let mut busiest: Option<(f64, Option<i64>)> = None;
        for window in ["5h", "7d"] {
            if let Some(u) = num(&format!("anthropic-ratelimit-unified-{window}-utilization")) {
                let u = if u > 1.0 { u / 100.0 } else { u };
                let reset = num(&format!("anthropic-ratelimit-unified-{window}-reset")).map(|r| r as i64);
                if busiest.is_none_or(|(b, _)| u > b) {
                    busiest = Some((u, reset));
                }
            }
        }
        if let Some((u, reset)) = busiest {
            s.utilization = Some(u.clamp(0.0, 1.0));
            s.resets_at = reset;
        }
        if let Some(r) = num("anthropic-ratelimit-unified-reset")
            && (s.limited || s.resets_at.is_none())
        {
            s.resets_at = Some(r as i64);
        }

        // Per-limit remaining counts (API keys), tightest wins.
        let mut tightest: Option<(f64, Option<i64>)> = None;
        let mut consider = |limit: Option<f64>, remaining: Option<f64>, reset: Option<i64>| {
            if let (Some(l), Some(r)) = (limit, remaining)
                && l > 0.0
            {
                let frac = (r / l).clamp(0.0, 1.0);
                if tightest.is_none_or(|(t, _)| frac < t) {
                    tightest = Some((frac, reset));
                }
            }
        };
        for kind in ["requests", "tokens", "input-tokens", "output-tokens"] {
            consider(num(&format!("anthropic-ratelimit-{kind}-limit")), num(&format!("anthropic-ratelimit-{kind}-remaining")), h(&format!("anthropic-ratelimit-{kind}-reset")).and_then(rfc3339));
            consider(num(&format!("x-ratelimit-limit-{kind}")), num(&format!("x-ratelimit-remaining-{kind}")), h(&format!("x-ratelimit-reset-{kind}")).and_then(|v| duration_from(v, now)));
        }
        if let Some((frac, reset)) = tightest {
            s.remaining = Some(frac);
            if s.resets_at.is_none() {
                s.resets_at = reset;
            }
        }
        s
    }

    /// One line for status output and the audit log.
    pub fn describe(&self) -> String {
        let mut parts = vec![];
        if self.limited {
            parts.push(format!("provider refused (status {})", self.status));
        }
        if let Some(u) = self.utilization {
            parts.push(format!("{:.0}% of the busiest window used", u * 100.0));
        }
        if let Some(r) = self.remaining {
            parts.push(format!("{:.0}% of the tightest limit left", r * 100.0));
        }
        if let Some(t) = self.resets_at {
            parts.push(format!("resets at {}", chrono::DateTime::from_timestamp(t, 0).map_or(t.to_string(), |d| d.with_timezone(&chrono::Local).format("%H:%M").to_string())));
        } else if let Some(s) = self.retry_after {
            parts.push(format!("retry after {s}s"));
        }
        if parts.is_empty() {
            parts.push("no quota information in the provider's responses".into());
        }
        parts.join(", ")
    }
}

fn rfc3339(v: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(v).ok().map(|d| d.timestamp())
}

/// OpenAI's reset durations: `1s`, `6m0s`, `250ms`, `1h2m3.5s`.
fn duration_from(v: &str, now: i64) -> Option<i64> {
    let mut total = 0.0;
    let mut num = String::new();
    let mut chars = v.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() || c == '.' {
            num.push(c);
            continue;
        }
        let unit = if c == 'm' && chars.peek() == Some(&'s') {
            chars.next();
            0.001
        } else {
            match c {
                'h' => 3600.0,
                'm' => 60.0,
                's' => 1.0,
                _ => return None,
            }
        };
        total += num.parse::<f64>().ok()? * unit;
        num.clear();
    }
    if !num.is_empty() || total < 0.0 {
        return None;
    }
    Some(now + total.ceil() as i64)
}
