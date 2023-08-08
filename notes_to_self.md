Strace outputs arguments during the syscall execution, e.g.:

```
# in `strace echo ACEG`:

fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0x2), ...}) = 0
write(1, "ACEG\n", 5ACEG
)                   = 5
close(1)                                = 0
```

Seems like it starts outputting before the syscall exit stop

--

When exactly can ESRCH occur? Possibly, in all interactions with the tracee, something to keep an eye out for

The wait status is our friend. Most of the ESRCH won't happen if we handle the wait status correctly

BUT, there are a lot of edge cases still. See `Death under ptrace`: https://man7.org/linux/man-pages/man2/ptrace.2.html

--

libc crate is missing some siginfo_t fields

They are there, but under the `pad` field, and that field is deprecated

Just noticed they have some `unsafe` fns to get those values

While exploring that part of the code, i'm seeing a lot about unions, perhaps that's why they don't make those fields readily available

But why not have an `enum` instead? :thinking:

--

`PTRACE_GET_SYSCALL_INFO` only returns useful data if the `PTRACE_O_TRACESYSGOOD` options is set for the tracee beforehand

--

`execve` has a syscall info op of `PTRACE_SYSCALL_INFO_NONE` for some reason

I know it doesn't have an exit stop, but shouldn't it have an enter one? Maybe all "entry"s need to have an "exit" and syscalls like `execve` behave like that

Seems like exit_group has an entry without an exit, idk, weird
