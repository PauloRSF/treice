use std::{env, ffi::CString, path::Path};

use nix::{
    sys::ptrace,
    unistd::{execve, fork, ForkResult, Pid},
};

fn execve_into_tracee(executable_path: &Path) -> ! {
    ptrace::traceme().expect("Failed to mark tracee as traceable");

    let exec_path = CString::new(executable_path.to_str().unwrap()).unwrap();

    let mut tracee_args = vec![exec_path.clone()];

    tracee_args.extend(env::args().skip(2).map(|arg| CString::new(arg).unwrap()));

    let tracee_env = std::env::vars()
        .map(|(key, value)| {
            let env_item = format!("{key}={value}");
            CString::new(env_item).unwrap()
        })
        .collect::<Vec<_>>();

    execve(&exec_path, &tracee_args, &tracee_env).expect("Failed to execve");

    unreachable!()
}

pub fn spawn_tracee_process(executable_path: &Path) -> Pid {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => child,
        Ok(ForkResult::Child) => execve_into_tracee(executable_path),
        Err(_) => panic!("Fork failed"),
    }
}
