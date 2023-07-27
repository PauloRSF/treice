use std::{
    env,
    ffi::CString,
    path::{Path, PathBuf},
    process::exit,
};

use nix::{
    errno::Errno,
    sys::{ptrace, wait::waitpid},
    unistd::{execve, fork, ForkResult, Pid},
};
use syscalls::Sysno;

fn spawn_tracee_process(executable_path: &Path) -> Pid {
    match unsafe { fork() } {
        Err(_) => panic!("Fork failed"),
        Ok(ForkResult::Parent { child, .. }) => child,
        Ok(ForkResult::Child) => {
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
    }
}

fn find_executable_in_os_lookup_paths(executable_path: &PathBuf) -> Option<PathBuf> {
    match env::var("PATH") {
        Err(_) => None,
        Ok(path_var) => path_var
            .split(':')
            .map(|path| {
                let mut lookup_path = PathBuf::from(path);
                lookup_path.push(executable_path);
                lookup_path
            })
            .find(|lookup_path| lookup_path.exists()),
    }
}

fn find_absolute_executable_path(executable_path: &String) -> Option<PathBuf> {
    let executable_path_buf = PathBuf::from(executable_path);

    if executable_path_buf.is_absolute() && executable_path_buf.exists() {
        return Some(executable_path_buf);
    }

    find_executable_in_os_lookup_paths(&executable_path_buf)
}

fn main() {
    let executable_path_arg = env::args().skip(1).rev().last();

    if executable_path_arg.is_none() {
        eprintln!("No executable specified");
        exit(1);
    }

    let executable_path = find_absolute_executable_path(&executable_path_arg.unwrap());

    if executable_path.is_none() {
        eprintln!("Could not find executable");
        exit(2);
    }

    let tracee_pid = spawn_tracee_process(executable_path.unwrap().as_path());

    println!("Tracee PID: {tracee_pid}\n");

    loop {
        let wait_result = waitpid(tracee_pid, None);

        if let Err(Errno::ESRCH) = wait_result {
            println!("ESRCH after wait");
            exit(0);
        }

        if let Err(errno) = wait_result {
            eprintln!("Failed to wait for child process: {errno}");
            exit(3);
        }

        let registers = ptrace::getregs(tracee_pid);

        if let Err(Errno::ESRCH) = registers {
            println!("ESRCH after reading registers");
            exit(0);
        }

        if let Err(errno) = registers {
            eprintln!("Failed to read registers: {errno}");
            exit(4);
        }

        let syscall = Sysno::from(registers.unwrap().orig_rax as i32);

        println!("Syscall: {}", syscall);

        ptrace::syscall(tracee_pid, None).unwrap();
    }
}
