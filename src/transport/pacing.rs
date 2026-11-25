//! Built-in outbound request pacing & randomized human-like jitter to protect
//! personal Zalo accounts from automated burst detection.

use std::time::Duration;

use rand::Rng;
use tokio::{sync::Mutex, time::Instant};

/// Configures outbound request spacing and randomized jitter.
#[derive(Debug, Clone, Copy)]
pub struct PacingPolicy {
    /// Minimum interval enforced between consecutive write/action calls.
    pub min_gap: Duration,
    /// Additional uniform random delay `[0, max_jitter]` added to mimic human timing.
    pub max_jitter: Duration,
}

impl PacingPolicy {
    /// Disabled pacing (0 delay) — useful for local tests or read-heavy inspection.
    pub const fn unthrottled() -> Self {
        Self {
            min_gap: Duration::ZERO,
            max_jitter: Duration::ZERO,
        }
    }

    /// Balanced default for interactive chatbots (`250ms` gap + up to `350ms` jitter).
    pub const fn balanced() -> Self {
        Self {
            min_gap: Duration::from_millis(250),
            max_jitter: Duration::from_millis(350),
        }
    }

    /// Conservative human-like cadence (`900ms` gap + up to `1200ms` jitter)
    /// recommended when messaging unfamiliar users or broadcasting to groups.
    pub const fn human_like() -> Self {
        Self {
            min_gap: Duration::from_millis(900),
            max_jitter: Duration::from_millis(1200),
        }
    }
}

impl Default for PacingPolicy {
    fn default() -> Self {
        Self::balanced()
    }
}

/// Thread-safe async traffic shaper enforcing a `PacingPolicy` across tasks.
#[derive(Debug)]
pub struct TrafficPacer {
    policy: PacingPolicy,
    next_slot: Mutex<Instant>,
}

impl TrafficPacer {
    pub fn new(policy: PacingPolicy) -> Self {
        Self {
            policy,
            next_slot: Mutex::new(Instant::now()),
        }
    }

    pub fn policy(&self) -> PacingPolicy {
        self.policy
    }

    /// Awaits the next permitted outbound transmission window.
    pub async fn acquire(&self) {
        if self.policy.min_gap.is_zero() && self.policy.max_jitter.is_zero() {
            return;
        }

        let jitter = if self.policy.max_jitter.is_zero() {
            Duration::ZERO
        } else {
            let max_ms = self.policy.max_jitter.as_millis() as u64;
            let extra_ms = rand::thread_rng().gen_range(0..=max_ms);
            Duration::from_millis(extra_ms)
        };

        let target = {
            let mut guard = self.next_slot.lock().await;
            let now = Instant::now();
            let scheduled = (*guard).max(now) + self.policy.min_gap + jitter;
            *guard = scheduled;
            scheduled
        };

        tokio::time::sleep_until(target).await;
    }
}
