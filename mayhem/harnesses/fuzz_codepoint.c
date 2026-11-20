/* Codepoint decode/encode/classify and reverse iteration: utf8codepoint,
 * utf8codepointcalcsize, utf8codepointsize, utf8codepointvisualwidth, utf8islower/isupper,
 * utf8lwrcodepoint/uprcodepoint, utf8catcodepoint, utf8rcodepoint.
 * Reaches upstream fix 3972a1a7bb (utf8codepoint over-read on a truncated sequence). */
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  utf8_int8_t *s = fuzz_cstr(data, size);
  utf8_int8_t *p = s, *end;
  while ('\0' != *p) {
    utf8_int32_t cp = 0, lc, uc;
    utf8_int8_t *q = utf8codepoint(p, &cp);
    utf8_int8_t *enc = (utf8_int8_t *)malloc(4), *e;
    size_t sz;
    (void)utf8codepointcalcsize(p);
    sz = utf8codepointsize(cp);
    (void)utf8codepointvisualwidth(cp);
    (void)utf8islower(cp);
    (void)utf8isupper(cp);
    lc = utf8lwrcodepoint(cp);
    uc = utf8uprcodepoint(cp);
    (void)utf8codepointsize(lc);
    (void)utf8codepointsize(uc);
    e = utf8catcodepoint(enc, cp, 4);
    if (e && (size_t)(e - enc) != sz) abort(); /* encoder agrees with codepointsize */
    free(enc);
    p = q;
  }
  end = p;

  /* utf8rcodepoint walks back with no lower bound: it needs a lead byte somewhere before the
   * position it is given. Valid UTF-8 always starts with one, so only walk valid strings. */
  if (end > s && NULL == utf8valid(s)) {
    utf8_int8_t *r = end;
    while (r > s) {
      utf8_int32_t cp = 0;
      utf8_int8_t *prev = utf8rcodepoint(r, &cp);
      if (prev < s || prev >= r) abort();
      r = prev;
    }
  }
  free(s);
  return 0;
}
