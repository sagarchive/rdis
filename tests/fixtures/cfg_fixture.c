#include <stdint.h>
#include <stdlib.h>

volatile int cfg_sink;

__attribute__((noinline))
static int helper(int x) {
    return (x * 3) ^ (x >> 1);
}

__attribute__((noinline))
int branch_loop(int n) {
    int acc = 0;
    for (int i = 0; i < n; ++i) {
        if (i & 1) {
            acc += helper(i);
        } else {
            acc -= helper(i + 1);
        }
    }
    if (acc > 13) {
        cfg_sink = acc;
        return acc;
    }
    cfg_sink = -acc;
    return -acc;
}

int main(int argc, char **argv) {
    return branch_loop(argc + (argv != NULL));
}
