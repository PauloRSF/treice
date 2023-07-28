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
