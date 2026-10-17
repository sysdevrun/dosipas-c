/*
 * Minimal JSON parser and structural comparator for the dosipas-c tests.
 * Objects compare as unordered maps, arrays in order, numbers as int64 when
 * both sides are integers (dosipas-ts only emits integers) and as doubles
 * otherwise. Reports the path of the first difference.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef TJSON_H
#define TJSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { TJ_NULL, TJ_BOOL, TJ_NUMBER, TJ_STRING, TJ_ARRAY, TJ_OBJECT } tj_kind_t;

typedef struct tj_value {
    tj_kind_t kind;
    const char *str;      /* STRING: NUL-terminated (unescaped); OBJECT member: key */
    double num;
    int64_t inum;
    bool is_int;
    bool b;
    struct tj_value *child; /* ARRAY: first item; OBJECT: first member */
    struct tj_value *next;  /* next sibling */
    const char *key;        /* for OBJECT members */
    size_t count;
} tj_value_t;

/* Parse text; returns NULL on syntax error. Memory comes from malloc; free with tj_free. */
tj_value_t *tj_parse(const char *text, size_t len);
void tj_free(tj_value_t *v);
const tj_value_t *tj_get(const tj_value_t *obj, const char *key);
const tj_value_t *tj_at(const tj_value_t *arr, size_t i);

/* Compare expected against actual; returns true when equal, else writes
 * "<path>: <what>" into diff. */
bool tj_equal(const tj_value_t *expected, const tj_value_t *actual, char *diff, size_t cap);

#ifdef __cplusplus
}
#endif

#endif
