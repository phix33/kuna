# No-return wrappers called through GOT slots

`wrap.c` holds wrappers of no-return imports and their callers:
- `die` calls `exit(1)`;
- `die2` calls `exit` on both of its paths;
- the exported `vanish` calls `exit(3)`;
- `g` calls `error(1, …)` on a negative argument.

`f`, `f2` and `k` call the three wrappers. Two controls stay returning:
`maybe` exits on one path only, and `drop` tail-jumps to `free`. Their
callers are `m` and `u`. The hidden wrappers are `noinline` and
`visibility("hidden")`, so a caller reaches them by a direct call.

| Image | Built | Import calls |
| --- | --- | --- |
| `wrap_noplt_x86_64.so` | `-fno-plt` | through each import's `GLOB_DAT` slot (`call *exit@GOTPCREL(%rip)`); `k` reaches `vanish` through `vanish`'s own slot |
| `wrap_plt_x86_64.so` | default | through the PLT (`.plt` and `.plt.sec`) |

Built in this directory with Ubuntu's GCC 15.2.0 (`gcc-15` 15.2.0-16ubuntu1)
and GNU binutils 2.46 (`binutils-x86-64-linux-gnu` 2.46-3ubuntu2). The images
link no C library: the imports stay undefined. `${OUT}` is any scratch
directory. The commands reproduce the committed images byte for byte.

```sh
gcc -O2 -fPIC -fno-plt -fno-ident -c -o ${OUT}/wrap-got.o wrap.c
gcc -O2 -fPIC -fno-ident -c -o ${OUT}/wrap-plt.o wrap.c
gcc -shared -nostdlib -Wl,--build-id=none -o wrap_noplt_x86_64.so ${OUT}/wrap-got.o
gcc -shared -nostdlib -Wl,--build-id=none -o wrap_plt_x86_64.so ${OUT}/wrap-plt.o
```

| File | SHA-256 |
| --- | --- |
| `wrap.c` | `18412b92ef1dc1d1647330354dc1370426055a9ba99a2be544e896d1ca16212e` |
| `wrap_noplt_x86_64.so` | `06765cdf15fd98558ab78296e7a707ffded27e837850b0d42f0e286ac23f72a4` |
| `wrap_plt_x86_64.so` | `be6c20d51794958439f99f372438c25bb67219483652d70db583a24c367ac414` |

The companion assembly gives each returning status control a distinct result.
The two links contain identical code. Only the protected link can establish
that the GOT still names the import. GNU binutils 2.46 rebuilds them from this
directory with a caller-selected scratch directory.

```sh
as --64 -o "${TMPDIR:?}/status.o" status.s
ld -shared -z relro -o status_x86_64.so "$TMPDIR/status.o"
ld -shared -z norelro -o status_writable_x86_64.so "$TMPDIR/status.o"
```

The i386 executable passes zero on the stack while EDI holds seven.
Its small provider returns so the process exits with 47. GNU binutils 2.46
reproduces it with the same scratch directory.

```sh
as --32 --defsym PROVIDER=1 -o "${TMPDIR:?}/provider.o" status_i386.s
ld -m elf_i386 -shared -o "$TMPDIR/libstatus.so" "$TMPDIR/provider.o"
as --32 -o "$TMPDIR/status32.o" status_i386.s
ld -m elf_i386 -z relro --no-dynamic-linker -o status_i386 "$TMPDIR/status32.o" -L"$TMPDIR" -lstatus
```
