/*
 * dosipas-c: short ASCII ticket summary for small displays.
 *
 * Formats a decoded ticket into at most 14 lines of 33 columns, the layout of
 * tools/ticket_summary.mjs in the grow-GM69Pro project (a 400x300 e-paper with
 * an ASCII-only font). This is the only place in the library that rewrites
 * characters: accented Latin letters lose their accent, anything else outside
 * printable ASCII becomes '?', and '|' becomes '/'.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef DOSIPAS_SUMMARY_H
#define DOSIPAS_SUMMARY_H

#include "dosipas.h"
#include "dosipas_verify.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DOSIPAS_SUMMARY_COLUMNS 33
#define DOSIPAS_SUMMARY_MAX_LINES 14
#define DOSIPAS_SUMMARY_LINE_SIZE (DOSIPAS_SUMMARY_COLUMNS + 1)

/*
 * Fill `lines` (each DOSIPAS_SUMMARY_LINE_SIZE bytes, NUL-terminated) and
 * return the number of lines written (<= max_lines). `level2` is the result
 * of dosipas_verify_level2() for this ticket, or NULL when it was not run.
 */
int dosipas_summary(const dosipas_ticket_t *ticket, const dosipas_verify_result_t *level2,
                    char lines[][DOSIPAS_SUMMARY_LINE_SIZE], int max_lines);

/* Same, with the level 1 result too (NULL when no key was available). The
 * last lines then read "L1 signature VALID/INVALID" and, when the barcode has
 * one, "L2 signature VALID/INVALID". */
int dosipas_summary_ex(const dosipas_ticket_t *ticket, const dosipas_verify_result_t *level1,
                       const dosipas_verify_result_t *level2, char lines[][DOSIPAS_SUMMARY_LINE_SIZE], int max_lines);

/* Format Unix seconds as "YYYY-MM-DD HH:MMZ" (18 chars incl. NUL) into out. */
void dosipas_format_utc(int64_t unix_seconds, char out[18]);

/* Copy `src` (UTF-8) into `dst` as printable ASCII, at most `cap`-1 bytes. */
void dosipas_to_ascii(const char *src, char *dst, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* DOSIPAS_SUMMARY_H */
