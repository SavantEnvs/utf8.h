/* Case-sensitive search, span, tokenise and compare: utf8str, utf8chr, utf8rchr, utf8pbrk,
 * utf8spn, utf8cspn, utf8sep, utf8cmp, utf8ncmp.
 * Input: <haystack> 0x00 <needle/set>. */
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  utf8_int8_t *a, *b, *m;
  size_t la, lb;
  utf8_int32_t cp = 0;
  fuzz_split(data, size, &a, &la, &b, &lb);

  m = utf8str(a, b);
  if (m && (m < a || m > a + la)) abort();
  m = utf8pbrk(a, b);
  if (m && (m < a || m > a + la)) abort();
  if (utf8spn(a, b) > la) abort();
  if (utf8cspn(a, b) > la) abort();
  (void)utf8cmp(a, b);
  if (utf8cmp(a, a) != 0) abort();
  (void)utf8ncmp(a, b, lb);
  /* utf8coll and utf8fry are declared but not implemented upstream (README "Todo"). */

  if (lb) {
    (void)utf8codepoint(b, &cp);
    m = utf8chr(a, cp);
    if (m && (m < a || m > a + la)) abort();
    m = utf8rchr(a, cp);
    if (m && (m < a || m > a + la)) abort();
  }

  {
    /* utf8sep cuts its (mutable) string in place, strsep-style */
    utf8_int8_t *copy = fuzz_cstr((const uint8_t *)a, la), *cur = copy, *tok;
    while (NULL != (tok = utf8sep(&cur, b))) {
      (void)utf8len(tok);
    }
    free(copy);
  }
  free(a);
  free(b);
  return 0;
}
