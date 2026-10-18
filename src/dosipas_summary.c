/*
 * dosipas-c: ASCII summary lines (see dosipas_summary.h). Mirrors
 * tools/ticket_summary.mjs from grow-GM69Pro.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdarg.h>
#include <stdio.h>

#include "dosipas_internal.h"
#include "dosipas_summary.h"

/* Strip accents from Latin-1 Supplement and Latin Extended-A letters: what
 * String.normalize('NFD') + removing combining marks leaves for them. The
 * table was generated from the Unicode data (see tools/ in the repo history);
 * letters that do not decompose to one ASCII letter print as '?'. */
static char latin_base(uint32_t cp) {
    static const char table[0xC0 + 1] =
        "AAAAAA?CEEEEIIII?NOOOOO??UUUUY??"  /* U+00C0 */
        "aaaaaa?ceeeeiiii?nooooo??uuuuy?y"  /* U+00E0 */
        "AaAaAaCcCcCcCcDd??EeEeEeEeEeGgGg"  /* U+0100 */
        "GgGgHh??IiIiIiIiI???JjKk?LlLlLl?"  /* U+0120 */
        "???NnNnNn???OoOoOo??RrRrRrSsSsSs"  /* U+0140 */
        "SsTtTt??UuUuUuUuUuUuWwYyYZzZzZz?"; /* U+0160 */
    if (cp >= 0xc0 && cp < 0x180) return table[cp - 0xc0];
    return '?';
}

void dosipas_to_ascii(const char *src, char *dst, size_t cap) {
    size_t w = 0;
    if (cap == 0) return;
    if (!src) src = "";
    const uint8_t *p = (const uint8_t *)src;
    while (*p && w + 1 < cap) {
        uint32_t cp;
        unsigned extra;
        uint8_t c = *p;
        if (c < 0x80) { cp = c; extra = 0; }
        else if ((c & 0xe0) == 0xc0) { cp = c & 0x1f; extra = 1; }
        else if ((c & 0xf0) == 0xe0) { cp = c & 0x0f; extra = 2; }
        else if ((c & 0xf8) == 0xf0) { cp = c & 0x07; extra = 3; }
        else { cp = 0xfffd; extra = 0; }
        p++;
        for (unsigned i = 0; i < extra; i++) {
            if ((*p & 0xc0) != 0x80) { cp = 0xfffd; break; }
            cp = (cp << 6) | (*p++ & 0x3f);
        }
        char out;
        if (cp >= 0x300 && cp <= 0x36f) continue; /* combining mark: dropped */
        if (cp == '|') out = '/';
        else if (cp >= 0x20 && cp <= 0x7e) out = (char)cp;
        else if (cp >= 0xc0 && cp <= 0x17f) out = latin_base(cp);
        else out = '?';
        dst[w++] = out;
    }
    dst[w] = '\0';
}

/* Civil date from days since the epoch (Howard Hinnant). */
static void civil_from_days(int64_t z, int64_t *y, unsigned *m, unsigned *d) {
    z += 719468;
    int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    unsigned doe = (unsigned)(z - era * 146097);
    unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t yy = (int64_t)yoe + era * 400;
    unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    unsigned mp = (5 * doy + 2) / 153;
    *d = doy - (153 * mp + 2) / 5 + 1;
    *m = mp < 10 ? mp + 3 : mp - 9;
    *y = yy + (*m <= 2);
}

void dosipas_format_utc(int64_t t, char out[18]) {
    int64_t days = t / 86400, rem = t % 86400;
    if (rem < 0) { rem += 86400; days--; }
    int64_t y;
    unsigned m, d;
    civil_from_days(days, &y, &m, &d);
    snprintf(out, 18, "%04lld-%02u-%02u %02lld:%02lldZ", (long long)y, m, d, (long long)(rem / 3600), (long long)((rem % 3600) / 60));
}

typedef struct {
    char (*lines)[DOSIPAS_SUMMARY_LINE_SIZE];
    int max, n;
} sum_t;

static void add(sum_t *s, const char *label, const char *value) {
    char tmp[256];
    if (s->n >= s->max) return;
    snprintf(tmp, sizeof tmp, "%s%s", label, value ? value : "");
    dosipas_to_ascii(tmp, s->lines[s->n], DOSIPAS_SUMMARY_LINE_SIZE);
    s->n++;
}

static void add_f(sum_t *s, const char *label, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void add_f(sum_t *s, const char *label, const char *fmt, ...) {
    char v[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(v, sizeof v, fmt, ap);
    va_end(ap);
    add(s, label, v);
}

static const char *vstr(const dosipas_value_t *seq, const char *name) {
    const dosipas_value_t *v = dosipas_value_field(seq, name);
    if (!v) return NULL;
    if (v->kind == DOSIPAS_V_STRING) return (const char *)v->u.data.ptr;
    if (v->kind == DOSIPAS_V_ENUMERATED) return dosipas_value_enum_name(v);
    return NULL;
}

static bool vint(const dosipas_value_t *seq, const char *name, int64_t *out) {
    const dosipas_value_t *v = dosipas_value_field(seq, name);
    if (!v || v->kind != DOSIPAS_V_INTEGER) return false;
    *out = v->u.i;
    return true;
}

int dosipas_summary(const dosipas_ticket_t *t, const dosipas_verify_result_t *level2, char lines[][DOSIPAS_SUMMARY_LINE_SIZE],
                    int max_lines) {
    return dosipas_summary_ex(t, NULL, level2, lines, max_lines);
}

int dosipas_summary_ex(const dosipas_ticket_t *t, const dosipas_verify_result_t *level1,
                       const dosipas_verify_result_t *level2, char lines[][DOSIPAS_SUMMARY_LINE_SIZE], int max_lines) {
    sum_t s = {lines, max_lines, 0};
    char buf[128], tbuf[18];
    if (!t || max_lines <= 0) return 0;
    const dosipas_level1_data_t *l1 = &t->level1Data;
    const dosipas_rail_ticket_t *rt = l1->dataSequence_count ? l1->dataSequence[0].decoded : NULL;
    const dosipas_issuing_detail_t *iss = rt ? rt->issuingDetail : NULL;

    /* "<format> <dataFormat> issuer <issuerNum ?? securityProviderNum ?? l1.securityProviderNum>" */
    const char *fmt0 = l1->dataSequence_count && l1->dataSequence[0].dataFormat ? l1->dataSequence[0].dataFormat : "";
    if (iss && iss->has_issuerNum) snprintf(buf, sizeof buf, "%s %s issuer %d", t->format, fmt0, iss->issuerNum);
    else if (iss && iss->has_securityProviderNum) snprintf(buf, sizeof buf, "%s %s issuer %d", t->format, fmt0, iss->securityProviderNum);
    else if (l1->has_securityProviderNum) snprintf(buf, sizeof buf, "%s %s issuer %d", t->format, fmt0, l1->securityProviderNum);
    else snprintf(buf, sizeof buf, "%s %s issuer %s", t->format, fmt0, l1->securityProviderIA5 ? l1->securityProviderIA5 : "undefined");
    add(&s, "", buf);

    if (iss && iss->intercodeIssuing && iss->intercodeIssuing->networkId.ptr) {
        const dosipas_bytes_t *net = &iss->intercodeIssuing->networkId;
        size_t w = 0;
        for (uint32_t i = 0; i < net->len && w + 3 < sizeof buf; i++) w += (size_t)snprintf(buf + w, sizeof buf - w, "%02x", net->ptr[i]);
        add(&s, "Intercode network ", buf);
    }
    int64_t ts;
    if (dosipas_issuing_time(t, &ts)) dosipas_format_utc(ts, tbuf);
    else snprintf(tbuf, sizeof tbuf, "?");
    add(&s, "Issued ", tbuf);

    if (rt && rt->travelerDetail && rt->travelerDetail->traveler_count) {
        const dosipas_traveler_t *tr = &rt->travelerDetail->traveler[0];
        snprintf(buf, sizeof buf, "%s%s%s", tr->firstName ? tr->firstName : "", tr->firstName && tr->lastName ? " " : "",
                 tr->lastName ? tr->lastName : "");
        add(&s, "", buf);
        if (tr->has_yearOfBirth && tr->yearOfBirth)
            add_f(&s, "Born ", "%d-%02d-%02d", tr->yearOfBirth, tr->has_monthOfBirth ? tr->monthOfBirth : 0,
                  tr->has_dayOfBirthInMonth ? tr->dayOfBirthInMonth : 0);
    }

    if (rt && rt->transportDocument_count && rt->transportDocument[0].ticket_key) {
        const dosipas_transport_document_t *doc = &rt->transportDocument[0];
        const dosipas_value_t *v = doc->ticket_value;
        const char *info = vstr(v, "infoText");
        if (info) snprintf(buf, sizeof buf, "%s: %s", doc->ticket_key, info);
        else snprintf(buf, sizeof buf, "%s", doc->ticket_key);
        add(&s, "", buf);
        const dosipas_open_ticket_t *o = doc->openTicket;
        if (o && iss) {
            int64_t from, until;
            if (dosipas_open_ticket_validity_window(o, iss, &from, &until)) {
                dosipas_format_utc(from, tbuf);
                add(&s, "From  ", tbuf);
                dosipas_format_utc(until, tbuf);
                add(&s, "Until ", tbuf);
            }
        }
        /* Route: first viaStations region, stationNum ?? stationIA5 joined by '>' */
        const dosipas_value_t *regions = dosipas_value_field(v, "validRegion");
        const dosipas_value_t *via = NULL, *train = NULL;
        for (const dosipas_value_t *r = regions ? regions->u.child : NULL; r; r = r->next) {
            const char *k = dosipas_value_choice_key(r);
            if (k && !via && strcmp(k, "viaStations") == 0) via = r->u.child;
            if (k && !train && strcmp(k, "trainLink") == 0) train = r->u.child;
        }
        const dosipas_value_t *route = via ? dosipas_value_field(via, "route") : NULL;
        if (route && route->aux) {
            size_t w = 0;
            buf[0] = 0;
            for (const dosipas_value_t *st = route->u.child; st && w + 2 < sizeof buf; st = st->next) {
                int64_t num;
                const char *ia5 = vstr(st, "stationIA5");
                if (vint(st, "stationNum", &num)) w += (size_t)snprintf(buf + w, sizeof buf - w, "%s%lld", w ? ">" : "", (long long)num);
                else w += (size_t)snprintf(buf + w, sizeof buf - w, "%s%s", w ? ">" : "", ia5 ? ia5 : "undefined");
            }
            add(&s, "Route ", buf);
        }
        if (train) {
            int64_t num, dep = 0;
            const char *ia5 = vstr(train, "trainIA5");
            bool has_dep = vint(train, "departureTime", &dep);
            char tn[32];
            if (vint(train, "trainNum", &num)) snprintf(tn, sizeof tn, "%lld", (long long)num);
            else snprintf(tn, sizeof tn, "%s", ia5 ? ia5 : "undefined");
            if (has_dep) add_f(&s, "Train ", "%s dep %02lld:%02lld", tn, (long long)(dep / 60), (long long)(dep % 60));
            else add_f(&s, "Train ", "%s dep NaN:NaN", tn);
        }
        /* "<classCode> class, 1x adult, ..." */
        const char *cls = vstr(v, "classCode");
        size_t w = (size_t)snprintf(buf, sizeof buf, "%s class", cls ? cls : "");
        const dosipas_value_t *tariffs = dosipas_value_field(v, "tariffs");
        bool first = true;
        for (const dosipas_value_t *x = tariffs ? tariffs->u.child : NULL; x && w + 4 < sizeof buf; x = x->next) {
            int64_t np = 1;
            vint(x, "numberOfPassengers", &np);
            const char *pt = vstr(x, "passengerType");
            w += (size_t)snprintf(buf + w, sizeof buf - w, "%s%lldx %s", first ? ", " : ", ", (long long)np, pt ? pt : "");
            first = false;
        }
        add(&s, "", buf);
        int64_t price;
        if (vint(v, "price", &price)) {
            int fract = iss ? iss->currencyFract : 2;
            if (fract < 0) fract = 0;
            if (fract > 6) fract = 6;
            int64_t div = 1;
            for (int i = 0; i < fract; i++) div *= 10;
            int64_t whole = price / div, frac = price % div;
            if (frac < 0) frac = -frac;
            if (fract) add_f(&s, "Price ", "%s%lld.%0*lld %s", (price < 0 && whole == 0) ? "-" : "", (long long)whole, fract, (long long)frac, iss && iss->currency ? iss->currency : "");
            else add_f(&s, "Price ", "%lld %s", (long long)whole, iss && iss->currency ? iss->currency : "");
        }
    }

    if (level1) add(&s, "", level1->valid ? "L1 signature VALID" : "L1 signature INVALID");
    if (t->level2Signature.ptr && t->level2Signature.len) {
        if (!level2) add(&s, "", "L2 signature not verifiable");
        else add(&s, "", level2->valid ? "L2 signature VALID" : "L2 signature INVALID");
    } else if (!level1) {
        add(&s, "", "L1 signed, key not checked");
    }
    return s.n;
}
