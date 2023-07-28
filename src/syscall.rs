use libc::{c_void, user_regs_struct};
use nix::{sys::ptrace, unistd::Pid};
use syscalls::Sysno;

fn decode_text_at_address(tracee_pid: &Pid, address: u64, char_count: u64) -> String {
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

fn format_address(address: u64) -> String {
    match address {
        0 => String::from("NULL"),
        addr => format!("0x{addr}"),
    }
}

pub fn print_syscall_data(tracee_pid: &Pid, registers: &user_regs_struct) {
    let syscall = Sysno::from(registers.orig_rax as i32);

    let arguments = match syscall {
        Sysno::close => vec![registers.rdi.to_string()],
        Sysno::brk => vec![format_address(registers.rdi)],
        Sysno::exit_group => vec![registers.rdi.to_string()],
        Sysno::write => vec![
            registers.rdi.to_string(),
            decode_text_at_address(tracee_pid, registers.rsi, registers.rdx),
            registers.rdx.to_string(),
        ],
        _ => Vec::default(),
    };

    print!("[{}]: {}", syscall.id(), syscall.name());

    if arguments.len() == 0 {
        println!()
    } else {
        println!("({})", arguments.join(", "))
    }
}
