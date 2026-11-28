extern void observe(int, int);
extern void strlen(float);

void forward(int x, int y) { observe(x, y); }
void forward_float(float x) { strlen(x); }

int use_worker(int);
int typed(int x) { return use_worker(x + 2) + x; }

extern void vf(int);
void fixed(int x) { vf(x); }

extern void profile_var(int);
void fixed_profile(int x) { profile_var(x); }
