use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Tracks the request and wall-clock budgets of a scan.
pub struct BudgetTracker {
    remaining: AtomicU64,
    deadline: Option<Instant>,
}

impl BudgetTracker {
    pub fn new(request_budget: u64, duration_budget: Option<Duration>) -> Self {
        Self {
            remaining: AtomicU64::new(request_budget),
            deadline: duration_budget.map(|duration| Instant::now() + duration),
        }
    }

    /// Atomically reserves one request slot. Returns false when the budget is
    /// exhausted.
    pub fn try_take(&self) -> bool {
        loop {
            let current = self.remaining.load(Ordering::Relaxed);
            if current == 0 {
                return false;
            }
            if self
                .remaining
                .compare_exchange(current, current - 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    pub fn exhausted(&self) -> bool {
        self.requests_exhausted() || self.time_exceeded()
    }

    pub fn requests_exhausted(&self) -> bool {
        self.remaining.load(Ordering::Relaxed) == 0
    }

    pub fn time_exceeded(&self) -> bool {
        self.deadline
            .map(|deadline| Instant::now() >= deadline)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::BudgetTracker;
    use std::time::Duration;

    #[test]
    fn budget_is_exhausted_after_capacity() {
        let tracker = BudgetTracker::new(3, None);
        assert!(tracker.try_take());
        assert!(tracker.try_take());
        assert!(tracker.try_take());
        assert!(!tracker.try_take());
        assert!(tracker.exhausted());
    }

    #[test]
    fn duration_budget_expires() {
        let tracker = BudgetTracker::new(100, Some(Duration::from_millis(10)));
        std::thread::sleep(Duration::from_millis(30));
        assert!(tracker.exhausted());
    }
}
