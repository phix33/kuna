# MIPS target-selection and import-flow fixtures

These original sources cover O32 BE/LE generic MIPS and Octeon machine flags,
and PIC import continuations with local/exported helpers, stripped/unstripped
symbols and stack protection on/off. N32/N64 provide 64-bit-register controls.
The CLI tests use committed images and need no compiler or emulator.

Regenerate with GCC 7.3 from the Octeon toolchain, a GNU assembler supporting
both byte orders, GNU multiarch ld and matching MIPS strip:

```sh
python3 build.py --cc "$MIPS_CC" --assembler "$MIPS_AS" \
  --ld "$MIPS_LD" --strip "$MIPS_STRIP" --nm "$MIPS_NM"
```

`provenance.json` records source/image/tool SHA-256 values, compiler and linker
flags, and pre-strip function addresses. These addresses locate functions in
test output; they are not assertions supplied to the decompiler. Compiler
assembly is passed unchanged to the assembler. No target libc is linked.

`duplicate` must preserve both copies, its terminator store and return.
`unknown_then_store` must retain the store and continuation after an import
with no known declaration. Stack protection introduces a genuinely non-returning
import. A lazy-binding resolver saves the caller return in t7 and transfers
through t9; it does not return into the following stub. Decoding that transfer
as an ordinary returning call makes each stub fall through into the next one.

The existing `floatret_chain_mips_O0` regression separately pins previously
broken output shared by base and head. A differential comparison alone cannot
establish its correctness. Compiler-fixture coverage and optional execution
are separate from the general public-image regression sweep.

For optional execution validation, use the same compiler/assembler/linker and
QEMU's O32 BE/LE user emulators:

```sh
python3 replay.py --kuna "$KUNA" --specs "$KUNA_SPECS" --cc "$MIPS_CC" \
  --assembler "$MIPS_AS" --ld "$MIPS_LD" --qemu-be "$QEMU_MIPS" \
  --qemu-le "$QEMU_MIPSEL" --out "$RESULTS"
```

The replay compiles each unchanged recovered helper body at O0 and O2 and
executes it beside the original source. Independent checks cover returned
pointers, both copies, the terminator and an adjacent canary for 41 lengths.
It requires no target libc. Missing arguments, compiler failures and execution
failures are errors. This optional check supplements the mandatory sealed-image
CLI tests; it is not a dependency of normal CI.

## MIPS import declarations

The O32 PIC callers in `abi/calls-hard.so` and `abi/calls-soft.so`
forward arguments to imports used by single-call LLVM witnesses in another
unit. LLVM emits each call's DWARF origin and return PC. The shared awk
script selects PIC assembly and initializes gp at entry so the assembler
emits a CALL16 load and JALR call for the same target. GNU ld retains these
relocations. The hard-float build uses the standard linkage-name attribute
and the soft-float build the legacy MIPS attribute.

The versioned provider is needed at link time. An import with a single
required version checks the mapping from the retained relocation to the
dynamic symbol. Two assembler aliases resolve
to different symbols from their source declarations. Section collection
removes a third witness while preserving its debug declaration. The
soft-float image also carries a live GNU call site with a truncated
declaration of `partial`. Its parsed prefix has the same two typed integers as the complete declaration.
A nested subprogram declaration precedes the call-site DIE. The complete declaration stands alone in the
hard-float image.

`slots/scoped.so` covers nested namespaces, references, typedefs and a static
class member. In the stripped `slots/o32-shared.so`, two GOT slots contain
the same stub address.

Set `TMPDIR` to a writable scratch directory. Run `sh abi/build.sh` and
`sh slots/build.sh` with `MIPS_CC` (GCC 7.3.0), `CLANG` and `LLC` (LLVM
21.1.8), and `MIPS_LD`, `OBJCOPY` and `READELF` (GNU binutils
2.47.20260726) set to the corresponding executables.

| Tool or output | SHA-256 |
| --- | --- |
| GCC | `5d26f5ed013593e77d0237dac6f3179f68cdbb681f8c20d7948444b7ff3e0b49` |
| Clang | `412bbe8c60571a1eb06f48fde89635033621caeb01a9b4ee76d46711bae8e932` |
| ld | `2865846ece2642439cfae404ef930bfc5494c4babd2347757878b8f0f8f761cf` |
| objcopy | `f4cee3fbde6906b10a4dba6c3543281fb5ccdbab4d8ba1c6acc560b4131f2ba2` |
| llc | `935bdae46915daba23b279efebc04400c085c56a8536dea633f1f5a96c9fd382` |
| `abi/calls-hard.so` | `908e4c7bef1f3c4de840f0b3f982d8789ce9b947f81a389946c97db6ad26acf1` |
| `abi/calls-soft.so` | `383571920c2b4fcef13f86705e631301ef97720614bcb27ef65fb92fa4bb76e6` |
| `readelf` | `97af8aa8807d5874bb2c1bf1af9b0702bb87d2457f8ec784b143d1ea824b45b4` |
| `slots/o32-shared.so` | `767f2528e9d3f724dc5bb4e737c064a91fbfae76b9c28162496338311b7f3a47` |
| `slots/scoped.so` | `5fc4fc93f682f849692ee7c94c4599dccfb2f619ab591f4a142d9cf17bb26f81` |


The `source-name` pair contains the same O32 PIC code and DWARF 5 call-site
origins. The declarations use ordinary C names. Only `linked.so` retains
the CALL16/JALR relocations. The freestanding `strlen` declaration exercises a
conflict with a library prototype. A second compilation unit uses Clang
profiling debug information, which identifies calls to `worker` and `puts`
while omitting the types and parameters of both returning imports. LLVM
also inlines the call to `worker` into the typed caller. A C23 variadic
declaration conflicts with the fixed declaration of `vf`. A profiling-only
copy exercises the same conflict after the variadic marker is stripped. Rebuild with
`sh source-name/build.sh` using `CLANG`, `LLC`, `MIPS_LD` and `TMPDIR`
as above. Set `LLVM_LINK` and `OPT` to LLVM 21.1.8's corresponding tools.

| Tool or output | SHA-256 |
| --- | --- |
| llvm-link | `e5a6455cbcc37547a58c5443ef1529f5430bb73cf26dcf37aaacde4ec4aa6516` |
| opt | `f3a0c71473eb573797c003382bbe096e6a6468f4da5caf406246f2dbb5e86531` |
| `source-name/linked.so` | `3dfe69e2df1d34d8c9a9631bf3f49029a823a1f8d7a940c749d52932b66296b7` |
| `source-name/ordinary.so` | `1d07fc6343d542bae332f78578b899c18e6b9a8eff3150f789a9cf35c4bcab45` |
