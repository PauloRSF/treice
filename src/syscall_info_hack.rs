use std::mem;

use libc::{c_void, ptrace_syscall_info};
use nix::{errno::Errno, unistd::Pid, Result};

// This is pretty much copied from https://github.com/nix-rust/nix/pull/2006
// since nix doesn't support PTRACE_GET_SYSCALL_INFO yet. When it is merged
// i'll use the nix impl instead

#[derive(Debug)]
pub struct SyscallInfo {
    /// Type of system call stop
    pub op: SyscallInfoOp,
    /// AUDIT_ARCH_* value; see seccomp(2)
    pub arch: u32,
    /// CPU instruction pointer
    pub instruction_pointer: u64,
    /// CPU stack pointer
    pub stack_pointer: u64,
}

#[derive(Debug)]
pub enum SyscallInfoOp {
    None,
    /// System call entry.
    Entry {
        /// System call number.
        nr: u64,
        /// System call arguments.
        args: [u64; 6],
    },
    /// System call exit.
    Exit {
        /// System call return value.
        ret_val: i64,
        /// System call error flag.
        is_error: u8,
    },
    /// PTRACE_EVENT_SECCOMP stop.
    Seccomp {
        /// System call number.
        nr: u64,
        /// System call arguments.
        args: [u64; 6],
        /// SECCOMP_RET_DATA portion of SECCOMP_RET_TRACE return value.
        ret_data: u32,
    },
}

impl SyscallInfo {
    pub fn from_raw(raw: ptrace_syscall_info) -> Result<SyscallInfo> {
        let op = match raw.op {
            libc::PTRACE_SYSCALL_INFO_NONE => Ok(SyscallInfoOp::None),
            libc::PTRACE_SYSCALL_INFO_ENTRY => Ok(SyscallInfoOp::Entry {
                nr: unsafe { raw.u.entry.nr as _ },
                args: unsafe { raw.u.entry.args },
            }),
            libc::PTRACE_SYSCALL_INFO_EXIT => Ok(SyscallInfoOp::Exit {
                ret_val: unsafe { raw.u.exit.sval },
                is_error: unsafe { raw.u.exit.is_error },
            }),
            libc::PTRACE_SYSCALL_INFO_SECCOMP => Ok(SyscallInfoOp::Seccomp {
                nr: unsafe { raw.u.seccomp.nr as _ },
                args: unsafe { raw.u.seccomp.args },
                ret_data: unsafe { raw.u.seccomp.ret_data },
            }),
            _ => Err(Errno::EINVAL),
        }?;

        Ok(SyscallInfo {
            op,
            arch: raw.arch,
            instruction_pointer: raw.instruction_pointer,
            stack_pointer: raw.stack_pointer,
        })
    }
}

pub fn getsyscallinfo(pid: Pid) -> Result<SyscallInfo> {
    let mut data = mem::MaybeUninit::uninit();

    unsafe {
        Errno::result(libc::ptrace(
            libc::PTRACE_GET_SYSCALL_INFO,
            libc::pid_t::from(pid),
            mem::size_of::<ptrace_syscall_info>() as *mut c_void,
            data.as_mut_ptr() as *mut _ as *mut c_void,
        ))
        .map(|_| 0)?;
    }
    SyscallInfo::from_raw(unsafe { data.assume_init() })
}
