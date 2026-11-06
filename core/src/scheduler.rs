// SPDX-License-Identifier: MIT OR Apache-2.0
//! Sampling interval policy: a base interval while the UI is focused, slowed down when it is not.

use std::time::Duration;

use crate::error::{Error, Result};

/// Multiplier applied to the base interval while the UI is unfocused or minimized.
pub const UNFOCUSED_MULTIPLIER: u32 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamplingScheduler {
    base: Duration,
    max: Duration,
    focused: bool,
}

impl SamplingScheduler {
    /// `base` is used while focused; `max` caps the slowed-down interval.
    pub fn new(base: Duration, max: Duration) -> Result<Self> {
        if base.is_zero() {
            return Err(Error::InvalidInput("base interval must be non-zero".into()));
        }
        if max < base {
            return Err(Error::InvalidInput("max interval must be >= base".into()));
        }
        Ok(Self {
            base,
            max,
            focused: true,
        })
    }

    pub fn set_focused(&mut self, focused: bool) {
        self.focused = focused;
    }

    pub fn is_focused(&self) -> bool {
        self.focused
    }

    /// Interval to wait before the next sample.
    pub fn next_interval(&self) -> Duration {
        if self.focused {
            self.base
        } else {
            self.base.saturating_mul(UNFOCUSED_MULTIPLIER).min(self.max)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slows_down_when_unfocused_and_caps_at_max() {
        let mut s =
            SamplingScheduler::new(Duration::from_secs(1), Duration::from_secs(10)).unwrap();
        assert_eq!(s.next_interval(), Duration::from_secs(1));
        s.set_focused(false);
        assert_eq!(s.next_interval(), Duration::from_secs(4));

        let capped =
            SamplingScheduler::new(Duration::from_secs(5), Duration::from_secs(10)).unwrap();
        let mut capped = capped;
        capped.set_focused(false);
        assert_eq!(capped.next_interval(), Duration::from_secs(10));
    }

    #[test]
    fn rejects_invalid_bounds() {
        assert!(SamplingScheduler::new(Duration::ZERO, Duration::from_secs(1)).is_err());
        assert!(SamplingScheduler::new(Duration::from_secs(2), Duration::from_secs(1)).is_err());
    }
}
