# treice

`treice` is a crappy strace clone that i'm building to learn more about strace and the ptrace syscall

## How to run

Just run it like strace:

```sh
cargo run <executable path> <args>
```

For the time being, the executable path must be the executable's absolute path (i.e. to trace `echo`, use `/usr/bin/echo`)

