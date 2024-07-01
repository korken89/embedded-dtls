//! # Helpers for creating the framed queues.
//!
//! There is one `std` aimed and one `no_std` embedded aimed.

#[cfg(any(test, feature = "tokio-queue"))]
pub use std::*;

#[cfg(feature = "bb-queue")]
pub use no_std::*;

#[cfg(any(test, feature = "tokio-queue"))]
mod std {
    use defmt_or_log::derive_format_or_debug;
    use tokio::sync::mpsc::{channel, Receiver as InnerReceiver, Sender as InnerSender};

    /// The queue is closed.
    #[derive_format_or_debug]
    #[derive(Copy, Clone, PartialEq, Eq)]
    pub struct Closed;

    /// Create a framed queue with specific maximum depth in number of packets.
    pub fn framed_queue(depth: usize) -> (Sender, Receiver) {
        let (s, r) = channel(depth);

        (
            Sender(s),
            Receiver {
                recv: r,
                store: None,
            },
        )
    }

    /// Sender half of the queue.
    pub struct Sender(InnerSender<Vec<u8>>);

    impl crate::ApplicationDataSender for Sender {
        type Error = Closed;

        async fn send(&mut self, data: impl AsRef<[u8]>) -> Result<(), Self::Error> {
            self.0.send(data.as_ref().into()).await.map_err(|_| Closed)
        }
    }

    /// Receiver half of the queue.
    pub struct Receiver {
        recv: InnerReceiver<Vec<u8>>,
        store: Option<Vec<u8>>,
    }

    impl crate::ApplicationDataReceiver for Receiver {
        type Error = Closed;

        async fn peek(&mut self) -> Result<impl AsRef<[u8]>, Self::Error> {
            if self.store.is_none() {
                self.store = Some(self.recv.recv().await.ok_or(Closed)?);
            }
            self.store.as_ref().ok_or(Closed)
        }

        fn pop(&mut self) -> Result<(), Self::Error> {
            self.store = None;
            Ok(())
        }
    }
}

#[cfg(feature = "bb-queue")]
mod no_std {
    use bbqueue::{
        framed::{FrameConsumer, FrameGrantR, FrameProducer},
        BBBuffer,
    };
    use core::{convert::Infallible, future::poll_fn, task::Poll};
    use defmt_or_log::derive_format_or_debug;
    use rtic_common::waker_registration::CriticalSectionWakerRegistration;

    /// A framed queue built onto of `BBQueue`.
    pub struct FramedQueue<const N: usize> {
        buffer: BBBuffer<N>,
        sender_waker: CriticalSectionWakerRegistration,
        receiver_waker: CriticalSectionWakerRegistration,
    }

    impl<const N: usize> FramedQueue<N> {
        /// Create a new framed queue.
        pub const fn new() -> Self {
            FramedQueue {
                buffer: BBBuffer::new(),
                sender_waker: CriticalSectionWakerRegistration::new(),
                receiver_waker: CriticalSectionWakerRegistration::new(),
            }
        }

        /// Split the queue into a sender/receiver pair. Return an error if the queue is already
        /// split.
        pub fn split(&mut self) -> Result<(Sender<N>, Receiver<N>), ()> {
            let (p, c) = self.buffer.try_split_framed().map_err(|_| ())?;

            Ok((
                Sender {
                    inner: p,
                    queue: self,
                },
                Receiver {
                    inner: c,
                    queue: self,
                    grant: None,
                },
            ))
        }
    }

    /// Sender half of the queue.
    pub struct Sender<'a, const N: usize> {
        inner: FrameProducer<'a, N>,
        queue: &'a FramedQueue<N>,
    }

    /// If the input data is larger than the maximum supported size.
    #[derive_format_or_debug]
    #[derive(Copy, Clone, PartialEq, Eq)]
    pub struct LargerThanMaxSize;

    impl<'a, const N: usize> crate::ApplicationDataSender for Sender<'a, N> {
        type Error = LargerThanMaxSize;

        async fn send(&mut self, data: impl AsRef<[u8]>) -> Result<(), Self::Error> {
            let data = data.as_ref();

            if data.len() > N {
                return Err(LargerThanMaxSize);
            }

            let mut g = poll_fn(|cx| {
                self.queue.sender_waker.register(cx.waker());

                match self.inner.grant(data.len()) {
                    Ok(g) => Poll::Ready(g),
                    Err(_) => Poll::Pending, // Queue is full.
                }
            })
            .await;

            g.copy_from_slice(data);
            g.commit(data.len());

            self.queue.receiver_waker.wake();

            Ok(())
        }
    }

    /// Receiver half of the queue.
    pub struct Receiver<'a, const N: usize> {
        inner: FrameConsumer<'a, N>,
        queue: &'a FramedQueue<N>,
        grant: Option<FrameGrantR<'a, N>>,
    }

    impl<'a, const N: usize> crate::ApplicationDataReceiver for Receiver<'a, N> {
        type Error = Infallible;

        async fn peek(&mut self) -> Result<impl AsRef<[u8]>, Self::Error> {
            self.grant = Some(
                poll_fn(|cx| {
                    self.queue.receiver_waker.register(cx.waker());

                    match self.inner.read() {
                        Some(r) => Poll::Ready(r),
                        None => Poll::Pending,
                    }
                })
                .await,
            );

            Ok(self.grant.as_deref().unwrap())
        }

        fn pop(&mut self) -> Result<(), Self::Error> {
            if let Some(grant) = self.grant.take() {
                grant.release();
            }

            self.queue.sender_waker.wake();

            Ok(())
        }
    }
}
