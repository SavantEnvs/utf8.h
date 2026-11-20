/* utf8nvalid / utf8valid / utf8makevalid: the validator and the in-place repair.
 * Deliberately calls no utf8codepoint-based API directly, so a utf8nvalid over-read
 * (upstream fix 963d7cbf3b) is not masked by another function crashing first. */
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* n-bounded validation over a buffer with no terminator */
  utf8_int8_t *raw = fuzz_raw(data, size);
  utf8_int8_t *bad = utf8nvalid(raw, size);
  if (bad && (bad < raw || bad >= raw + size)) abort(); /* must point inside the n bytes */
  free(raw);

  /* NUL-terminated validation, then repair in place */
  utf8_int8_t *s = fuzz_cstr(data, size);
  size_t len = strlen((const char *)s);
  bad = utf8valid(s);
  if (bad && (bad < s || bad >= s + len)) abort();
  if (0 != utf8makevalid(s, '?')) abort();      /* '?' <= 0x7f is always accepted */
  if (strlen((const char *)s) > len) abort();    /* repair never grows the string */
  (void)utf8valid(s);
  free(s);
  return 0;
}
