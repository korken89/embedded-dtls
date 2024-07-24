use core::{
    cell::UnsafeCell,
    future::poll_fn,
    mem::MaybeUninit,
    sync::atomic::{AtomicBool, Ordering},
    task::Poll,
};

use super::atomic_waker::AtomicWaker;

/// FIXME: docs
pub struct Signal<T> {
    inner: UnsafeCell<MaybeUninit<T>>,
    available: AtomicBool,
    send_waker: AtomicWaker,
    recv_waker: AtomicWaker,
}

unsafe impl<T> Send for Signal<T> {}
unsafe impl<T: Send> Sync for Signal<T> {}

impl<T> Signal<T> {
    /// Create a new signal.
    pub const fn new() -> Self {
        Self {
            inner: UnsafeCell::new(MaybeUninit::uninit()),
            available: AtomicBool::new(false),
            send_waker: AtomicWaker::new(),
            recv_waker: AtomicWaker::new(),
        }
    }

    /// Try to send a value via the signal.
    pub fn try_send(&self, value: T) -> bool {
        if !self.available.load(Ordering::Acquire) {
            unsafe { (self.inner.get() as *mut T).write(value) };
            self.available.store(true, Ordering::Release);
            self.recv_waker.wake();
            true
        } else {
            false
        }
    }

    /// Send a value via the signal.
    pub async fn send(&self, value: T) {
        // Wait for space.
        poll_fn(|cx| {
            if self.available.load(Ordering::Acquire) {
                self.send_waker.register(cx.waker());

                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;

        unsafe { (self.inner.get() as *mut T).write(value) };
        self.available.store(true, Ordering::Release);
        self.recv_waker.wake();
    }

    /// Receive a value via the signal.
    pub async fn recv(&self) -> T {
        poll_fn(|cx| {
            if self.available.load(Ordering::Acquire) {
                let val = unsafe { (self.inner.get() as *const T).read() };
                self.available.store(false, Ordering::Release);
                self.send_waker.wake();
                Poll::Ready(val)
            } else {
                self.recv_waker.register(cx.waker());

                Poll::Pending
            }
        })
        .await
    }
}
