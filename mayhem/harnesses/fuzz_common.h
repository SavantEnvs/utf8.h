/* Shared helpers for the utf8.h fuzz harnesses.
 *
 * The bugs this library has had are 1-3 byte over-reads past the NUL terminator or past the
 * n-byte limit, so every buffer handed to utf8.h is an EXACT-size heap allocation: padding
 * (stack arrays, rounded-up mallocs) would hide them from ASan. */
#ifndef UTF8_FUZZ_COMMON_H
#define UTF8_FUZZ_COMMON_H
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "utf8.h"

/* malloc(n) copy with NO terminator, for the n-bounded functions (utf8nvalid, utf8nlen, ...). */
static utf8_int8_t *fuzz_raw(const uint8_t *data, size_t n) {
  utf8_int8_t *p = (utf8_int8_t *)malloc(n ? n : 1);
  if (n) memcpy(p, data, n);
  return p;
}

/* malloc(n+1) copy with exactly one trailing NUL, for the NUL-terminated functions. */
static utf8_int8_t *fuzz_cstr(const uint8_t *data, size_t n) {
  utf8_int8_t *p = (utf8_int8_t *)malloc(n + 1);
  if (n) memcpy(p, data, n);
  p[n] = '\0';
  return p;
}

/* Split the input at its first 0x00 byte into two NUL-terminated strings a and b
 * (b stops at the next 0x00, as any C string would). */
static void fuzz_split(const uint8_t *data, size_t size, utf8_int8_t **a, size_t *la,
                       utf8_int8_t **b, size_t *lb) {
  const uint8_t *z = (const uint8_t *)memchr(data, 0, size);
  size_t na = z ? (size_t)(z - data) : size;
  const uint8_t *rest = z ? z + 1 : data + size;
  size_t nrest = size - na - (z ? 1 : 0);
  const uint8_t *z2 = (const uint8_t *)memchr(rest, 0, nrest);
  size_t nb = z2 ? (size_t)(z2 - rest) : nrest;
  *a = fuzz_cstr(data, na);
  *la = na;
  *b = fuzz_cstr(rest, nb);
  *lb = nb;
}
#endif
