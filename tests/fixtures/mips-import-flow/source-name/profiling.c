extern int worker(int, int);
extern int puts(const char *);

int use_worker(int x) { return worker(x, 26) + 5; }
int use_puts(const char *text) { return puts(text + 4) + 1; }
