use core::{
    cell::UnsafeCell,
    future::poll_fn,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicBool, Ordering},
    task::{Poll, Waker},
};

/// Simple Mutex to share a T between the `select` arms in `Connection::run`.
/// If this is locked, then the `do_poll` will be set, causing the waker to be woken on unlock,
/// causing the `select` to be polled again.
///
/// Must only be used in a select statement where no external tasks are spawned.
pub struct Mutex<T> {
    inner: UnsafeCell<T>,
    locked: AtomicBool,
    do_poll: AtomicBool,
}

unsafe impl<T> Send for Mutex<T> {}
unsafe impl<T> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    /// Create a new mutex.
    pub const fn new(val: T) -> Self {
        Self {
            inner: UnsafeCell::new(val),
            locked: AtomicBool::new(false),
            do_poll: AtomicBool::new(false),
        }
    }

    /// Lock the shared resource and gain access to it.
    pub async fn lock(&self) -> MutexGuard<T> {
        poll_fn(|cx| {
            // Try lock.
            if self
                .locked
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                Poll::Ready(MutexGuard {
                    parent: self,
                    to_wake: cx.waker().clone(),
                })
            } else {
                // If locked, poll the select when done.
                self.do_poll.store(true, Ordering::Relaxed);

                Poll::Pending
            }
        })
        .await
    }

    /// Try to lock the shared resource.
    pub async fn try_lock(&self) -> Option<MutexGuard<T>> {
        poll_fn(|cx| {
            // Try lock.
            if self
                .locked
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                Poll::Ready(Some(MutexGuard {
                    parent: self,
                    to_wake: cx.waker().clone(),
                }))
            } else {
                Poll::Ready(None)
            }
        })
        .await
    }
}

/// This type signifies exclusive access to the object protected by `Mutex`.
pub struct MutexGuard<'a, T> {
    parent: &'a Mutex<T>,
    to_wake: Waker,
}

impl<'a, T> Deref for MutexGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: This is protected via the `locked` atomic flag.
        unsafe { &*self.parent.inner.get() }
    }
}

impl<'a, T> DerefMut for MutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: This is protected via the `locked` atomic flag.
        unsafe { &mut *self.parent.inner.get() }
    }
}

impl<'a, T> Drop for MutexGuard<'a, T> {
    fn drop(&mut self) {
        // Unlock.
        self.parent.locked.store(false, Ordering::Release);

        // Poll if requested.
        if self.parent.do_poll.load(Ordering::Relaxed) {
            self.parent.do_poll.store(false, Ordering::Relaxed);
            self.to_wake.wake_by_ref();
        }
    }
}
