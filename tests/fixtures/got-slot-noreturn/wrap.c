/* Wrappers of no-return imports and their callers. Built with -fno-plt, each
   call to an import goes through its GOT slot; built with the PLT, through its
   stub. */
void exit(int) __attribute__((noreturn));
void error(int, int, const char *, ...);
void free(void *);
int seen;

__attribute__((noinline, visibility("hidden"))) void die(void) { exit(1); }
__attribute__((noinline, visibility("hidden"))) void die2(int x) { if (x) exit(4); seen = x; exit(5); }
__attribute__((noinline, visibility("hidden"))) void maybe(int x) { if (x) exit(6); }
__attribute__((noinline, visibility("hidden"))) void drop(void *p) { free(p); }
void vanish(void) { exit(3); }

int f(int x) { if (x) die(); seen = x; return x + 1; }
int f2(int x) { if (x > 1) die2(x); seen = x; return x + 2; }
int g(int x) { if (x < 0) error(1, 0, "bad %d", x); seen = x; return x * 3; }
int k(int x) { if (x == 7) vanish(); seen = x; return x + 4; }
int m(int x) { maybe(x); seen = x; return x + 5; }
int u(void *p) { drop(p); seen = 1; return 6; }
