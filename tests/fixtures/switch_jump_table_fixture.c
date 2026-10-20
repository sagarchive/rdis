/* Independent optimized x86-64 switch-table fixture; covered by the RDIS repository MIT license. */
volatile int switch_table_sink;

#define CASE_FUNCTION(n) \
    __attribute__((noinline, used)) int switch_table_case_##n(int x) { \
        switch_table_sink += x + (n); \
        return switch_table_sink; \
    }

CASE_FUNCTION(0)
CASE_FUNCTION(1)
CASE_FUNCTION(2)
CASE_FUNCTION(3)
CASE_FUNCTION(4)
CASE_FUNCTION(5)
CASE_FUNCTION(6)
CASE_FUNCTION(7)
CASE_FUNCTION(8)
CASE_FUNCTION(9)
CASE_FUNCTION(10)
CASE_FUNCTION(11)

__attribute__((noinline, used)) int truth_switch_jump_table(int x) {
    switch (x) {
    case 0: return switch_table_case_0(x);
    case 1: return switch_table_case_1(x);
    case 2: return switch_table_case_2(x);
    case 3: return switch_table_case_3(x);
    case 4: return switch_table_case_4(x);
    case 5: return switch_table_case_5(x);
    case 6: return switch_table_case_6(x);
    case 7: return switch_table_case_7(x);
    case 8: return switch_table_case_8(x);
    case 9: return switch_table_case_9(x);
    case 10: return switch_table_case_10(x);
    case 11: return switch_table_case_11(x);
    default: return -1;
    }
}

int main(int argc, char **argv) {
    return truth_switch_jump_table(argc + (argv != 0));
}
