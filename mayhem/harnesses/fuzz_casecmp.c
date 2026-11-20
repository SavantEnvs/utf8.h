/* Case-insensitive compare and search plus in-place case conversion: utf8casecmp,
 * utf8ncasecmp, utf8casestr, utf8ncasestr, utf8lwr, utf8upr (and the case-mapping tables).
 * Input: <a> 0x00 <b>; the first byte of a (if any) also picks the ncasecmp limit. */
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  utf8_int8_t *a, *b;
  size_t la, lb, k;
  int c1, c2;
  fuzz_split(data, size, &a, &la, &b, &lb);
  k = la ? (unsigned char)a[0] : 0;

  c1 = utf8casecmp(a, b);
  c2 = utf8casecmp(b, a);
  if ((c1 < 0 && c2 <= 0) || (c1 > 0 && c2 >= 0) || (c1 == 0 && c2 != 0)) abort();
  if (utf8casecmp(a, a) != 0) abort();
  (void)utf8ncasecmp(a, b, k);
  (void)utf8ncasecmp(a, b, la);
  (void)utf8casestr(a, b);
  (void)utf8casestr(b, a);
  {
    /* the length-bounded search gets unterminated, exact-size buffers */
    utf8_int8_t *ra = fuzz_raw((const uint8_t *)a, la);
    utf8_int8_t *rb = fuzz_raw((const uint8_t *)b, lb);
    utf8_int8_t *m = utf8ncasestr(ra, la, rb, lb);
    if (m && (m < ra || m > ra + la)) abort();
    free(ra);
    free(rb);
  }
  utf8lwr(a);
  utf8upr(b);
  free(a);
  free(b);
  return 0;
}
