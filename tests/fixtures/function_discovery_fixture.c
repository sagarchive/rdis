/* Deterministic function-discovery truth corpus; MIT license of the RDIS repository. */
typedef int (*truth_unary_fn)(int);
volatile int truth_sink;

__attribute__((noinline, used)) int truth_leaf(int x) {
    return x * 3 + 1;
}

__attribute__((noinline, used)) int truth_branch_loop(int n) {
    int acc = 0;
    for (int i = 0; i < n; ++i) {
        if (i & 1) acc += truth_leaf(i);
        else acc -= i + 1;
    }
    return acc;
}

__attribute__((noinline, used)) int truth_switch(int x) {
    switch (x) {
        case 0: return 17;
        case 1: return 23;
        case 2: return 31;
        case 3: return 41;
        case 4: return 53;
        case 5: return 67;
        case 6: return 79;
        case 7: return 83;
        case 8: return 97;
        case 9: return 101;
        default: return -1;
    }
}

__attribute__((noinline, used)) int truth_tail(int x) {
    return truth_leaf(x);
}

__attribute__((noinline, used)) int truth_address_taken(int x) {
    volatile int scratch[8];
    for (int i = 0; i < 8; ++i) scratch[i] = x + i;
    return scratch[0] * scratch[7];
}

__attribute__((noinline, used)) int truth_indirect(truth_unary_fn fn, int x) {
    return fn(x);
}

__attribute__((noinline, used)) int truth_entry(int argc, char **argv) {
    int x = argc + (argv != 0);
    truth_sink = truth_branch_loop(x) + truth_switch(x) + truth_tail(x) +
                 truth_leaf(x) + truth_indirect(truth_address_taken, x);
    return truth_sink;
}
