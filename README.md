# Linux Kernel Driver Compiler (KDC)

An extra abstraction layer for Kernel Drivers. Define your own write/read logic.

## Get Started

Use this one-liner for initial demo.

```shell
make && \
./build/compiler/compiler samples/test.c build/test.xz && \
./build/user/runner-user build/test.xz 1 && \
./build/user/runner-user build/test.xz 2
```

## Disclaimer

For educational purposes.
