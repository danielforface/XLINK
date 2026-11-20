//! Session-local additive-increase/multiplicative-decrease frame pacing.
//! A single slow send must not lock the producer to the requested FPS.
use std::time::Duration;

#[derive(Debug)]
pub struct AdaptiveFrameRate {
    requested: u16,
    current: u16,
    healthy_samples: u16,
}

impl AdaptiveFrameRate {
    pub fn new(requested: u16) -> Self {
        let requested = requested.clamp(1, 60);
        Self { requested, current: requested, healthy_samples: 0 }
    }

    pub fn current(&self) -> u16 { self.current }

    /// Update an authenticated technician's requested FPS budget while
    /// retaining the adaptive congestion protection.
    pub fn set_requested(&mut self, fps: u16) -> bool {
        let next = fps.clamp(1, 60);
        if self.requested == next { return false; }
        self.requested = next;
        self.current = self.current.min(self.requested);
        self.healthy_samples = 0;
        true
    }

    pub fn interval(&self) -> Duration {
        Duration::from_millis((1000 / u64::from(self.current)).max(1))
    }

    /// Observe elapsed encode + network send time. Returns true if pacing changed.
    pub fn observe(&mut self, elapsed: Duration) -> bool {
        let previous = self.current;
        let budget = self.interval();
        if elapsed > budget.mul_f64(1.25) {
            // Back off quickly under transport congestion or overloaded encoding.
            self.current = (self.current.saturating_mul(3) / 4).max(1);
            if self.current == previous && previous > 1 {
                self.current -= 1;
            }
            self.healthy_samples = 0;
        } else if elapsed < budget.mul_f64(0.55) {
            self.healthy_samples = self.healthy_samples.saturating_add(1);
            if self.healthy_samples >= 30 {
                self.current = self.current.saturating_add(1).min(self.requested);
                self.healthy_samples = 0;
            }
        } else {
            self.healthy_samples = 0;
        }
        self.current != previous
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn congestion_reduces_fps_and_recovery_is_gradual() {
        let mut rate = AdaptiveFrameRate::new(30);
        assert_eq!(rate.current(), 30);
        assert!(rate.observe(Duration::from_millis(300)));
        assert!(rate.current() < 30);
        let reduced = rate.current();
        for _ in 0..30 {
            rate.observe(Duration::from_millis(1));
        }
        assert_eq!(rate.current(), reduced + 1);
    }

    #[test]
    fn limits_are_enforced_under_repeated_extremes() {
        let mut rate = AdaptiveFrameRate::new(120);
        assert_eq!(rate.current(), 60);
        for _ in 0..500 {
            rate.observe(Duration::from_secs(5));
        }
        assert_eq!(rate.current(), 1);
        for _ in 0..10_000 {
            rate.observe(Duration::ZERO);
        }
        assert_eq!(rate.current(), 60);
    }

    #[test]
    fn technician_controls_fps_without_disabling_backpressure() {
        let mut rate = AdaptiveFrameRate::new(30);
        assert!(rate.set_requested(10));
        assert_eq!(rate.current(), 10);
        assert!(rate.set_requested(60));
        for _ in 0..30 { rate.observe(Duration::ZERO); }
        assert_eq!(rate.current(), 11);
        assert!(rate.set_requested(0));
        assert_eq!(rate.current(), 1);
    }

    #[test]
    fn requested_minimum_remains_one() {
        let mut rate = AdaptiveFrameRate::new(0);
        assert_eq!(rate.current(), 1);
        rate.observe(Duration::from_secs(50));
        assert_eq!(rate.current(), 1);
    }
}
