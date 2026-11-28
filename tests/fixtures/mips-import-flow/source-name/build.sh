#!/bin/sh
set -eu
: "${CLANG:?}" "${LLC:?}" "${LLVM_LINK:?}" "${OPT:?}" "${MIPS_LD:?}"
cd "$(dirname "$0")"
work=$(mktemp -d "${TMPDIR:?set TMPDIR to a scratch directory}/mips-source-name.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
compile_ir() {
    unit=$1
    shift
    "$CLANG" --target=mips-linux-gnu -O2 -gdwarf-5 "$@" -fdebug-compilation-dir=. \
        -ffreestanding -fno-optimize-sibling-calls -S -emit-llvm "$unit.c" -o "$work/$unit.ll"
}
compile_ir calls
compile_ir profiling -gline-tables-only -fdebug-info-for-profiling
"$LLVM_LINK" "$work/calls.ll" "$work/profiling.ll" -o "$work/combined.bc"
"$OPT" -passes='default<O2>' "$work/combined.bc" -o "$work/inlined.bc"
assemble() {
    "$LLC" -emit-call-site-info "$1" -o "$work/direct.s"
    awk -f ../link-declarations.awk "$work/direct.s" > "$work/pic.s"
    "$CLANG" --target=mips-linux-gnu -fdebug-compilation-dir=. -c "$work/pic.s" -o "$2"
}
assemble "$work/inlined.bc" "$work/calls.o"
compile_ir variadic -std=c23
assemble "$work/variadic.ll" "$work/variadic.o"
compile_ir variadic -std=c23 -gline-tables-only -fdebug-info-for-profiling \
    -Dvf=profile_var -Dvariadic=profile_variadic
assemble "$work/variadic.ll" "$work/profile-variadic.o"
"$MIPS_LD" -m elf32btsmip -shared --build-id=none -z max-page-size=0x1000 \
    --emit-relocs "$work/calls.o" "$work/variadic.o" "$work/profile-variadic.o" -o linked.so
"$MIPS_LD" -m elf32btsmip -shared --build-id=none -z max-page-size=0x1000 \
    "$work/calls.o" "$work/variadic.o" "$work/profile-variadic.o" -o ordinary.so
