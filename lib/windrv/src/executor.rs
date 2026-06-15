// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Minimal kernel-only async executor.
//!
//! The Windows kernel cannot host a std async runtime. Futures are polled from
//! IRP completion callbacks; long-running work is queued onto `ExWorkItem`
//! worker threads. Wakers resume polling when an awaited IRP completes.

use core::future::Future;

pub struct KernelExecutor {
    // TODO(driver): task queue + ExWorkItem worker registration.
    _private: (),
}

impl KernelExecutor {
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Spawn a detached task driven by completion-callback wakers.
    pub fn spawn<F: Future<Output = ()> + Send + 'static>(&self, fut: F) {
        let _ = fut;
        todo!("enqueue future, poll on waker from IRP completion")
    }

    /// Block the current (PASSIVE_LEVEL) thread until `fut` resolves.
    pub fn block_on<F: Future>(&self, fut: F) -> F::Output {
        let _ = fut;
        todo!("poll loop with KeWaitForSingleObject on a waker event")
    }
}

impl Default for KernelExecutor {
    fn default() -> Self {
        Self::new()
    }
}
