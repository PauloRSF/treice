use libc::siginfo_t;
use nix::sys::signal::Signal;

pub fn print_signal_data(signal_info: &siginfo_t) {
    let signal_name = Signal::try_from(signal_info.si_signo)
        .map(|signal| signal.as_str())
        .unwrap_or("<unknown>");

    unsafe {
        println!(
            "--- {} {{si_signo={}, si_code={}, si_pid={}, si_uid={}}} ---",
            signal_name,
            signal_name,
            signal_info.si_code,
            signal_info.si_pid(),
            signal_info.si_uid()
        )
    }
}
