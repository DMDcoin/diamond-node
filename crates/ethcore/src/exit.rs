//! allows controlled shutdown of the node software.

use std::sync::Arc;

use parking_lot::{Condvar, Mutex};

#[derive(Debug)]
/// Status used to exit or restart the program.
pub struct ExitStatus {
    /// Whether the program panicked.
    panicking: bool,
    /// Whether the program should exit.
    should_exit: bool,
}

impl ExitStatus {
    /// new not panicking
    pub fn new() -> Self {
        ExitStatus {
            panicking: false,
            should_exit: false,
        }
    }

    /// new one that panics
    pub fn new_panicking() -> Self {
        ExitStatus {
            panicking: true,
            should_exit: true,
        }
    }

    /// regular exit wihout panic
    pub fn new_should_exit() -> Self {
        ExitStatus {
            panicking: false,
            should_exit: true,
        }
    }

    /// Signals the overlaying system to perform a shutdown.
    pub fn do_shutdown(self: &mut Self) {
        self.should_exit = true;
    }

    /// has someone requested a shutdown?
    pub fn should_exit(self: &Self) -> bool {
        return self.should_exit;
    }

    /// has someone requested a panic?
    pub fn is_panicking(self: &Self) -> bool {
        return self.panicking;
    }
}

/// Shutdown Manager allows engines to signal the system to shutdown.
pub struct ShutdownManager {
    exit_mutex: Arc<(Mutex<ExitStatus>, Condvar)>,
}

impl ShutdownManager {
    /// get's a Null Object that does not interact with the system at all.
    pub fn null() -> Self {
        return ShutdownManager {
            exit_mutex: Arc::new((
                Mutex::new(ExitStatus {
                    panicking: false,
                    should_exit: false,
                }),
                Condvar::new(),
            )),
        };
    }

    /// creates a new shutdown manager, use ::null() if you do not wish to provide a mutex.
    pub fn new(mutex_original: &Arc<(Mutex<ExitStatus>, Condvar)>) -> Self {
        return ShutdownManager {
            exit_mutex: mutex_original.clone(),
        };
    }

    /// demands a shutdown of the node software
    pub fn demand_shutdown(self: &Self) {
        self.exit_mutex.0.lock().do_shutdown();
        self.exit_mutex.1.notify_all();
    }
}
