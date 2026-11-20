/* utf8nlen / utf8nsize_lazy / utf8ncodepoint over an unterminated buffer, plus
 * utf8len / utf8size / utf8size_lazy over a NUL-terminated copy.
 * Reaches upstream fix 1e7c1da269 (utf8nlen over-read on a truncated trailing sequence).
 * Build with -DUTF8_FUZZ_NO_NCODEPOINT for revisions that predate utf8ncodepoint and
 * utf8nsize_lazy. */
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  utf8_int8_t *raw = fuzz_raw(data, size);
  size_t n;
  if (utf8nlen(raw, size) > size) abort(); /* at most one codepoint per byte */
  /* also a limit that can cut a multibyte sequence in half */
  if (size) (void)utf8nlen(raw, size - 1);
#ifndef UTF8_FUZZ_NO_NCODEPOINT
  if (utf8nsize_lazy(raw, size) > size) abort();
  {
    const utf8_int8_t *p = raw;
    size_t rem = size;
    while (rem > 0) {
      utf8_int32_t cp = 0;
      const utf8_int8_t *q = utf8ncodepoint(p, &cp, rem);
      if (!q) { p++; rem--; continue; }
      if (q <= p || (size_t)(q - p) > rem || cp < 0 || cp > 0x10ffff) abort();
      rem -= (size_t)(q - p);
      p = q;
    }
  }
#endif
  free(raw);

  utf8_int8_t *s = fuzz_cstr(data, size);
  n = strlen((const char *)s);
  if (utf8size(s) != n + 1) abort();
  if (utf8size_lazy(s) != n) abort();
  if (utf8len(s) > n) abort();
  free(s);
  return 0;
}
