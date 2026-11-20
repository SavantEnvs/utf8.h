/* Allocating and copying functions: utf8dup, utf8ndup, utf8dup_ex, utf8ndup_ex, utf8cpy,
 * utf8ncpy, utf8cat, utf8ncat. Destinations are exactly the size each function's contract
 * says it writes, so an overrun is an ASan report.
 * Input: <a> 0x00 <b>; the first byte of b (if any) picks the n limit. */
#include "fuzz_common.h"

static utf8_int8_t *fuzz_alloc(utf8_int8_t *user, size_t n) {
  (void)user;
  return (utf8_int8_t *)malloc(n);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  utf8_int8_t *a, *b, *d;
  size_t la, lb, n, sa, sb;
  fuzz_split(data, size, &a, &la, &b, &lb);
  n = lb ? (unsigned char)b[0] : la;
  sa = utf8size(a);
  sb = utf8size(b);

  d = utf8dup(a);
  if (!d || strcmp((const char *)d, (const char *)a) != 0) abort();
  free(d);
  d = utf8dup_ex(a, fuzz_alloc, NULL);
  free(d);
  d = utf8ndup(a, n);
  if (!d || strlen((const char *)d) > n) abort();
  free(d);
  d = utf8ndup_ex(b, n, fuzz_alloc, NULL);
  free(d);

  /* cpy + cat into exactly size(a) + size(b) - 1 bytes */
  d = (utf8_int8_t *)malloc(sa + sb - 1);
  utf8cpy(d, a);
  utf8cat(d, b);
  if (strlen((const char *)d) != la + lb) abort();
  free(d);

  /* ncpy writes exactly n bytes (like strncpy) */
  d = (utf8_int8_t *)malloc(n ? n : 1);
  utf8ncpy(d, a, n);
  free(d);

  /* ncat appends at most n bytes plus a terminator to a */
  d = (utf8_int8_t *)malloc(sa + n);
  memcpy(d, a, sa);
  utf8ncat(d, b, n);
  free(d);

  free(a);
  free(b);
  return 0;
}
