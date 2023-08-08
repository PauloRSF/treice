use std::{env, ffi::CString, path::Path};

use libc::{siginfo_t, user_regs_struct};
use nix::{
    sys::{
        ptrace,
        wait::{waitpid, WaitStatus},
    },
    unistd::{execve, fork, ForkResult, Pid},
};

use crate::{
    error::TreiceError,
    syscall_info_hack::{getsyscallinfo, SyscallInfo},
};

pub struct Tracee {
    pub pid: Pid,
    has_set_options: bool,
}

impl Tracee {
    pub fn new(pid: Pid) -> Self {
        Self {
            pid,
            has_set_options: false,
        }
    }

    pub fn wait(&self) -> Result<WaitStatus, TreiceError> {
        waitpid(self.pid, None).map_err(TreiceError::ChildWaitFailure)
    }

    pub fn get_signal_info(&self) -> Result<siginfo_t, TreiceError> {
        ptrace::getsiginfo(self.pid).map_err(TreiceError::SignalInfoReadFailure)
    }

    pub fn get_registers(&self) -> Result<user_regs_struct, TreiceError> {
        ptrace::getregs(self.pid).map_err(TreiceError::RegistersReadFailure)
    }

    pub fn get_syscall_info(&self) -> Result<SyscallInfo, TreiceError> {
        getsyscallinfo(self.pid).map_err(TreiceError::RegistersReadFailure)
    }

    pub fn set_tracing_options(&self) -> Result<(), TreiceError> {
        if !self.has_set_options {
            ptrace::setoptions(self.pid, ptrace::Options::PTRACE_O_TRACESYSGOOD)
                .map_err(TreiceError::OptionsSetFailure)
        } else {
            Ok(())
        }
    }
}

fn execve_into_tracee(executable_path: &Path) -> ! {
    ptrace::traceme().expect("Failed to mark tracee as traceable");

    let exec_path = CString::new(executable_path.to_str().unwrap()).unwrap();

    let mut tracee_args = vec![exec_path.clone()];

    tracee_args.extend(env::args().skip(2).map(|arg| CString::new(arg).unwrap()));

    let tracee_env = std::env::vars()
        .filter_map(|(key, value)| CString::new(format!("{key}={value}")).ok())
        .collect::<Vec<_>>();

    execve(&exec_path, &tracee_args, &tracee_env).expect("Failed to execve");

    unreachable!()
}

pub fn spawn_tracee<T: AsRef<Path>>(executable_path: T) -> Result<Tracee, TreiceError> {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => Ok(Tracee::new(child)),
        Ok(ForkResult::Child) => execve_into_tracee(executable_path.as_ref()),
        Err(errno) => Err(TreiceError::ForkFailure(errno)),
    }
}
