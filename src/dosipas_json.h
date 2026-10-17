/*
 * dosipas-c: JSON serializer.
 *
 * The output, once parsed, equals the dosipas-ts `decodeTicket` result
 * serialized with: Uint8Array -> lowercase hex string, undefined fields left
 * out, everything else (field names, enumeration names, CHOICE {key, value}
 * objects, numbers) as dosipas-ts produces it. Key order follows the schema.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef DOSIPAS_JSON_H
#define DOSIPAS_JSON_H

#include "dosipas.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Serialize a decoded ticket. Writes at most `cap` bytes (always NUL-terminated
 * when cap > 0) and stores the full length (without the NUL) in *needed, like
 * snprintf. Returns DOSIPAS_ERR_SMALL_BUFFER when the output was cut.
 */
dosipas_err_t dosipas_json_write(const dosipas_ticket_t *ticket, char *buf, size_t cap, size_t *needed);

/* Serialize any generic value (SEQUENCE -> object, SEQUENCE OF -> array, ...). */
dosipas_err_t dosipas_json_write_value(const dosipas_value_t *value, char *buf, size_t cap, size_t *needed);

#ifdef __cplusplus
}
#endif

#endif /* DOSIPAS_JSON_H */
