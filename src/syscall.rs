use std::ops::Neg;

use libc::{c_void, user_regs_struct};
use nix::{sys::ptrace, unistd::Pid};
use syscalls::Sysno;

use crate::{
    error::TreiceError,
    syscall_info_hack::{SyscallInfo, SyscallInfoOp},
    tracee::Tracee,
};

type Word = u64;

fn decode_text_at_address(tracee_pid: &Pid, address: Word, char_count: Word) -> String {
    let mut bytes: Vec<u8> = Vec::new();
    // number of [address] word reads to get all chars
    // dv 8 because x86_64 word = 8 bytes
    let number_of_reads = char_count / 8;

    for index in 0..=number_of_reads {
        let pointer = (address + index) as *mut c_void;
        let data = ptrace::read(*tracee_pid, pointer)
            .expect(format!("Failed to read data in <addr+{}:{:x}>", index, address).as_str());

        bytes.extend(data.to_ne_bytes().iter());
    }

    bytes.resize(char_count as usize, 0);

    format!("{:?}", String::from_utf8_lossy(&bytes))
}

fn format_address(address: Word) -> String {
    match address {
        0 => String::from("NULL"),
        addr => format!("0x{:x}", addr),
    }
}

const NO_RETURN_SYSCALLS: [Sysno; 4] = [
    Sysno::exit,
    Sysno::exit_group,
    Sysno::execve,
    Sysno::execveat,
];

pub fn syscall_does_not_return(syscall: &Sysno) -> bool {
    NO_RETURN_SYSCALLS.contains(syscall)
}

pub fn get_syscall(orig_rax: Word) -> Sysno {
    Sysno::from(orig_rax as i32)
}

const TODO_TAG: &str = "/* TODO */";

pub fn print_syscall_enter_data(tracee_pid: &Pid, registers: &user_regs_struct) {
    let syscall = get_syscall(registers.orig_rax);

    let arguments = match syscall {
        Sysno::close => vec![registers.rdi.to_string()],
        Sysno::brk | Sysno::set_tid_address => vec![format_address(registers.rdi)],
        Sysno::exit_group => vec![registers.rdi.to_string()],
        Sysno::munmap => vec![format_address(registers.rdi), registers.rsi.to_string()],
        Sysno::getrandom => vec![
            decode_text_at_address(tracee_pid, registers.rdi, registers.rsi),
            registers.rdx.to_string(),
            String::from(TODO_TAG),
        ],
        Sysno::mprotect => vec![
            format_address(registers.rdi),
            registers.rsi.to_string(),
            String::from(TODO_TAG),
        ],
        Sysno::mmap => vec![
            format_address(registers.rdi),
            registers.rsi.to_string(),
            String::from(TODO_TAG),
        ],
        Sysno::write => vec![
            registers.rdi.to_string(),
            decode_text_at_address(tracee_pid, registers.rsi, registers.rdx),
            registers.rdx.to_string(),
        ],
        _ => vec![String::from(TODO_TAG)],
    };

    print!("{}({})", syscall.name(), arguments.join(", "));
}

pub fn print_syscall_return_value(registers: &user_regs_struct) {
    let syscall = get_syscall(registers.orig_rax);

    // TODO: confirm that syscall returns are signed `long`s and check how
    // negative numbers are represented. (seems like it's just flipped)
    // This is buggy rn
    let signed_rax_hm = ((registers.rax ^ u64::MAX) as i32).neg();
    let signed_rax = signed_rax_hm - if signed_rax_hm > 0 { 1 } else { 0 };

    match syscall {
        Sysno::mmap | Sysno::brk => println!(" = {}", format_address(registers.rax)),
        _ => println!(" = {}", signed_rax),
    };
}

pub fn print_syscall_info(tracee: &Tracee, syscall_info: &SyscallInfo) -> Result<(), TreiceError> {
    let registers = tracee.get_registers()?;
    let syscall = get_syscall(registers.orig_rax);

    match syscall_info.op {
        SyscallInfoOp::Entry { .. } | SyscallInfoOp::None { .. } => {
            print_syscall_enter_data(&tracee.pid, &registers);

            if syscall_does_not_return(&syscall) {
                println!()
            }
        }
        SyscallInfoOp::Exit { .. } => print_syscall_return_value(&registers),
        _ => {}
    }

    Ok(())
}
