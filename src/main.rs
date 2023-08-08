use libc::{siginfo_t, SIGTRAP};
use nix::sys::{ptrace, wait::WaitStatus};

use treice::{
    error::{exit_with_error_code, TreiceError},
    exec::get_executable_path_from_args,
    syscall::print_syscall_info,
    tracee::spawn_tracee,
};

fn execute() -> Result<(), TreiceError> {
    let tracee = get_executable_path_from_args().and_then(spawn_tracee)?;

    println!("Tracee PID: {}\n", tracee.pid);

    loop {
        let tracee_status = tracee.wait()?;

        if let WaitStatus::Exited(_, code) = tracee_status {
            println!("+++ exited with {} +++", code);
            break;
        }

        if let WaitStatus::Signaled(_, signal, _) = tracee_status {
            println!("+++ killed by {} +++", signal);
            break;
        }

        tracee.set_tracing_options()?;


        let syscall_info = tracee.get_syscall_info()?;

        print_syscall_info(&tracee, &syscall_info)?;

        ptrace::syscall(tracee.pid, None).unwrap();
    }

    Ok(())
}

fn main() {
    if let Err(error) = execute() {
        eprintln!("{error}");
        exit_with_error_code(&error);
    }
}
