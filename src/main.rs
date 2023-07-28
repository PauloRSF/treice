use std::{env, process::exit};

use nix::{
    errno::Errno,
    sys::{ptrace, wait::waitpid},
};
use treice::{
    exec::find_absolute_executable_path, syscall::print_syscall_data, tracee::spawn_tracee_process,
};

fn main() {
    let executable_path_arg = match env::args().skip(1).rev().last() {
        Some(arg) => arg,
        None => {
            eprintln!("No executable specified");
            exit(1);
        }
    };

    let executable_path = match find_absolute_executable_path(&executable_path_arg) {
        Some(path) => path,
        None => {
            eprintln!("Could not find executable");
            exit(2);
        }
    };

    let tracee_pid = spawn_tracee_process(executable_path.as_path());

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

        let registers = match ptrace::getregs(tracee_pid) {
            Ok(regs) => regs,
            Err(Errno::ESRCH) => {
                println!("ESRCH after reading registers");
                exit(0);
            }
            Err(errno) => {
                eprintln!("Failed to read registers: {errno}");
                exit(4);
            }
        };

        // dbg!(registers);

        print_syscall_data(&tracee_pid, &registers);

        ptrace::syscall(tracee_pid, None).unwrap();
    }
}
