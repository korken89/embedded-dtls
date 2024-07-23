use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
    task::Waker,
};

/// Utility struct used to register and wake a waker across the select branches
pub struct AtomicWaker {
    waker: UnsafeCell<Option<Waker>>,
    locked: AtomicBool,
}

unsafe impl Send for AtomicWaker {}
unsafe impl Sync for AtomicWaker {}

impl AtomicWaker {
    pub const fn new() -> Self {
        Self {
            waker: UnsafeCell::new(None),
            locked: AtomicBool::new(false),
        }
    }

    fn with_waker(&self, f: impl FnOnce(&mut Option<Waker>)) {
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            // Safety:
            // 1. self.waker access is protected by self.locked against multiple exclusive borrows
            let maybe_waker = unsafe { &mut *self.waker.get() };
            f(maybe_waker);
            // FIXME: Memory ordering?
            self.locked.store(false, Ordering::Release);
        } else {
            defmt_or_log::panic!(
                "AtomicWaker access attempt when locked - called from two concurrent contexts?"
            );
        }
    }

    /// Register a waker. Overwrites the previous waker, if any.
    pub fn register(&self, new_waker: &Waker) {
        self.with_waker(|maybe_waker| match maybe_waker {
            Some(waker) if (waker.will_wake(new_waker)) => {}
            maybe_waker => {
                maybe_waker.replace(new_waker.clone());
            }
        });
    }

    /// Waker the registered waker, if any.
    pub fn wake(&self) {
        self.with_waker(|maybe_waker| {
            if let Some(waker) = maybe_waker {
                waker.wake_by_ref();
            }
        });
    }
}
