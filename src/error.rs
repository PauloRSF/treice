use core::fmt;
use std::process::exit;

use nix::errno::Errno;

#[derive(Debug)]
pub enum TreiceError {
    NoExecutableProvided,
    ExecutableNotFound,
    ForkFailure(Errno),
    ChildWaitFailure(Errno),
    SignalInfoReadFailure(Errno),
    RegistersReadFailure(Errno),
    OptionsSetFailure(Errno),
}

impl fmt::Display for TreiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TreiceError::NoExecutableProvided => f.write_str("No executable specified"),
            TreiceError::ExecutableNotFound => f.write_str("Could not find executable"),
            TreiceError::ForkFailure(errno) => {
                f.write_fmt(format_args!("Failed to fork tracer process: {errno}"))
            }
            TreiceError::ChildWaitFailure(errno) => {
                f.write_fmt(format_args!("Failed to wait for child process: {errno}"))
            }
            TreiceError::SignalInfoReadFailure(errno) => {
                f.write_fmt(format_args!("Failed to get signal info: {errno}"))
            }
            TreiceError::RegistersReadFailure(errno) => {
                f.write_fmt(format_args!("Failed to read registers: {errno}"))
            }
            TreiceError::OptionsSetFailure(errno) => f.write_fmt(format_args!(
                "Failed to set tracing options for the tracee: {errno}"
            )),
        }
    }
}

pub fn exit_with_error_code(error: &TreiceError) -> ! {
    let code = match error {
        TreiceError::NoExecutableProvided => 1,
        TreiceError::ExecutableNotFound => 2,
        TreiceError::ForkFailure(_) => 3,
        TreiceError::ChildWaitFailure(_) => 4,
        TreiceError::SignalInfoReadFailure(_) => 5,
        TreiceError::RegistersReadFailure(_) => 6,
        TreiceError::OptionsSetFailure(_) => 7,
    };

    exit(code)
}
