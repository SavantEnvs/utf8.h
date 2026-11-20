// Leaks are not the bug class this fleet fuzzes for; turn LeakSanitizer off at build time
// while ASan and UBSan stay fully active (SPEC §6.2 item 15).
extern "C" int __lsan_is_turned_off() { return 1; }
