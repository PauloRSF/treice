use std::{env, ffi::CString};

use nix::{
    sys::{ptrace, wait::waitpid},
    unistd::{self, fork, ForkResult, Pid},
};
use syscalls::Sysno;

fn exec_tracee() {
    ptrace::traceme().expect("Failed to mark tracee as traceable");

    let args = env::args().collect::<Vec<String>>();

    let tracee_args = args
        .iter()
        .skip(1)
        .cloned()
        .map(|arg| CString::new(arg).unwrap())
        .collect::<Vec<_>>();

    let exec_path = tracee_args[0].clone();

    let tracee_env = std::env::vars()
        .map(|(key, value)| format!("{key}={value}"))
        .map(|arg| CString::new(arg).unwrap())
        .collect::<Vec<_>>();

    unistd::execve(&exec_path.clone(), &tracee_args, &tracee_env)
        .expect("Failed to execve successfully");
}

fn spawn_tracee_process() -> Pid {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            return child;
        }
        Ok(ForkResult::Child) => {
            exec_tracee();
            unreachable!();
        }
        Err(_) => panic!("Fork failed"),
    };
}

fn main() {
    let tracee_pid = spawn_tracee_process();

    println!("Tracee PID: {tracee_pid}\n");

    loop {
        waitpid(tracee_pid, None)
            .expect("Should wait for child process to change or receive signal");

        let registers = ptrace::getregs(tracee_pid).expect("Failed to read registers");
        let syscall = Sysno::from(registers.orig_rax as i32);

        println!("Syscall: {}", syscall);

        ptrace::syscall(tracee_pid, None).unwrap();
    }
}
