/*
 * dosipas-c: ticket decoding flow (header sniffing, FCB records, Intercode 6
 * extensions, dynamic data), the typed view over the generic value tree, the
 * signed-bytes extraction and the time helpers. Mirrors dosipas-ts
 * decoder.ts / signed-data.ts / time-helpers.ts.
 *
 * SPDX-License-Identifier: MIT
 */
#include "dosipas_internal.h"

/* ------------------------------------------------------------------------- */
/* Binding helpers                                                           */
/* ------------------------------------------------------------------------- */

#define M(seq, name) ds_member((seq), DS_NAME_##name)

static bool b_i32(const dosipas_value_t *seq, uint16_t name, int32_t *out) {
    const dosipas_value_t *v = ds_member(seq, name);
    if (!v || v->kind != DOSIPAS_V_INTEGER) return false;
    *out = (int32_t)v->u.i;
    return true;
}

static bool b_i64(const dosipas_value_t *seq, uint16_t name, int64_t *out) {
    const dosipas_value_t *v = ds_member(seq, name);
    if (!v || v->kind != DOSIPAS_V_INTEGER) return false;
    *out = v->u.i;
    return true;
}

static bool b_bool(const dosipas_value_t *seq, uint16_t name, bool *out) {
    const dosipas_value_t *v = ds_member(seq, name);
    if (!v || v->kind != DOSIPAS_V_BOOLEAN) return false;
    *out = v->u.i != 0;
    return true;
}

static const char *b_str(const dosipas_value_t *seq, uint16_t name) {
    const dosipas_value_t *v = ds_member(seq, name);
    if (!v || (v->kind != DOSIPAS_V_STRING && v->kind != DOSIPAS_V_OID)) return NULL;
    return (const char *)v->u.data.ptr;
}

static const char *b_enum(const dosipas_value_t *seq, uint16_t name) {
    return dosipas_value_enum_name(ds_member(seq, name));
}

static dosipas_bytes_t b_bytes(const dosipas_value_t *seq, uint16_t name) {
    dosipas_bytes_t r = {NULL, 0};
    const dosipas_value_t *v = ds_member(seq, name);
    if (v && v->kind == DOSIPAS_V_BYTES) {
        r.ptr = v->u.data.ptr;
        r.len = v->u.data.len;
    }
    return r;
}

static const dosipas_value_t *b_list(const dosipas_value_t *seq, uint16_t name, size_t *count) {
    const dosipas_value_t *v = ds_member(seq, name);
    *count = 0;
    if (!v || v->kind != DOSIPAS_V_SEQUENCE_OF) return NULL;
    *count = v->aux;
    return v;
}

/* Returns false only when the arena is full. */
static bool b_i32_list(dosipas_arena_t *a, const dosipas_value_t *seq, uint16_t name, size_t *count, int32_t **out) {
    const dosipas_value_t *l = b_list(seq, name, count);
    *out = NULL;
    if (!l) return true;
    if (*count == 0) return true;
    int32_t *arr = (int32_t *)ds_arena_alloc(a, *count * sizeof *arr);
    if (!arr) return false;
    size_t i = 0;
    for (const dosipas_value_t *it = l->u.child; it && i < *count; it = it->next) arr[i++] = (int32_t)it->u.i;
    *out = arr;
    return true;
}

static bool b_i64_list(dosipas_arena_t *a, const dosipas_value_t *seq, uint16_t name, size_t *count, int64_t **out) {
    const dosipas_value_t *l = b_list(seq, name, count);
    *out = NULL;
    if (!l || *count == 0) return true;
    int64_t *arr = (int64_t *)ds_arena_alloc(a, *count * sizeof *arr);
    if (!arr) return false;
    size_t i = 0;
    for (const dosipas_value_t *it = l->u.child; it && i < *count; it = it->next) arr[i++] = it->u.i;
    *out = arr;
    return true;
}

static bool b_str_list(dosipas_arena_t *a, const dosipas_value_t *seq, uint16_t name, size_t *count,
                       const char ***out) {
    const dosipas_value_t *l = b_list(seq, name, count);
    *out = NULL;
    if (!l || *count == 0) return true;
    const char **arr = (const char **)ds_arena_alloc(a, *count * sizeof *arr);
    if (!arr) return false;
    size_t i = 0;
    for (const dosipas_value_t *it = l->u.child; it && i < *count; it = it->next)
        arr[i++] = it->kind == DOSIPAS_V_STRING ? (const char *)it->u.data.ptr : "";
    *out = arr;
    return true;
}

#define ALLOC(a, T) ((T *)ds_arena_alloc((a), sizeof(T)))
#define ALLOC_N(a, T, n) ((T *)ds_arena_alloc((a), sizeof(T) * (n)))

/* Decode nested UPER data (FCB record, Intercode extension, dynamic content)
 * best-effort like dosipas-ts: a malformed payload leaves *out NULL and
 * reports why in *err / *bit; the arena is rolled back. Only arena exhaustion
 * is a hard failure (returns false), so a tiny arena can never be mistaken for
 * a malformed ticket. */
static bool nested_decode(dosipas_arena_t *a, const uint8_t *data, uint32_t len, uint16_t root, dosipas_value_t **out,
                          dosipas_err_t *err, uint32_t *bit) {
    size_t mark = a->used;
    uint32_t fb = 0;
    *out = NULL;
    dosipas_err_t e = len ? dosipas_decode_value(data, len, root, a, out, &fb) : DOSIPAS_ERR_TRUNCATED;
    if (e == DOSIPAS_ERR_ARENA_FULL) return false;
    if (e != DOSIPAS_OK) {
        a->used = mark;
        *out = NULL;
    }
    if (err) *err = e;
    if (bit) *bit = fb;
    return true;
}

/* ------------------------------------------------------------------------- */
/* Typed binding of rail ticket data                                         */
/* ------------------------------------------------------------------------- */

static dosipas_geo_coordinate_t *bind_geo(dosipas_arena_t *a, const dosipas_value_t *seq) {
    if (!seq) return NULL;
    dosipas_geo_coordinate_t *g = ALLOC(a, dosipas_geo_coordinate_t);
    if (!g) return NULL;
    g->geoUnit = b_enum(seq, DS_NAME_geoUnit);
    g->coordinateSystem = b_enum(seq, DS_NAME_coordinateSystem);
    g->hemisphereLongitude = b_enum(seq, DS_NAME_hemisphereLongitude);
    g->hemisphereLatitude = b_enum(seq, DS_NAME_hemisphereLatitude);
    g->has_longitude = b_i64(seq, DS_NAME_longitude, &g->longitude);
    g->has_latitude = b_i64(seq, DS_NAME_latitude, &g->latitude);
    g->accuracy = b_enum(seq, DS_NAME_accuracy);
    return g;
}

static dosipas_extension_t *bind_extension(dosipas_arena_t *a, const dosipas_value_t *seq) {
    if (!seq) return NULL;
    dosipas_extension_t *e = ALLOC(a, dosipas_extension_t);
    if (!e) return NULL;
    e->extensionId = b_str(seq, DS_NAME_extensionId);
    e->extensionData = b_bytes(seq, DS_NAME_extensionData);
    return e;
}

/* Returns false only when the arena is full; *out stays NULL for anything
 * that is not a decodable Intercode issuing extension. */
static bool bind_intercode_issuing(dosipas_arena_t *a, const dosipas_extension_t *ext, dosipas_intercode_issuing_t **out) {
    *out = NULL;
    if (!ext || !ext->extensionId || !ext->extensionData.ptr) return true;
    if (!ds_is_intercode_issuing_extension(ext->extensionId)) return true;
    dosipas_value_t *v = NULL;
    if (!nested_decode(a, ext->extensionData.ptr, ext->extensionData.len, DS_ROOT_INTERCODE_ISSUING, &v, NULL, NULL))
        return false;
    if (!v) return true; /* like dosipas-ts: leave intercodeIssuing undefined */
    dosipas_intercode_issuing_t *ic = ALLOC(a, dosipas_intercode_issuing_t);
    if (!ic) return false;
    ic->value = v;
    ic->extensionId = ext->extensionId;
    b_i32(v, DS_NAME_intercodeVersion, &ic->intercodeVersion);
    b_i32(v, DS_NAME_intercodeInstanciation, &ic->intercodeInstanciation);
    ic->networkId = b_bytes(v, DS_NAME_networkId);
    const dosipas_value_t *pr = M(v, productRetailer);
    if (pr) {
        dosipas_product_retailer_t *r = ALLOC(a, dosipas_product_retailer_t);
        if (!r) return false;
        r->retailChannel = b_enum(pr, DS_NAME_retailChannel);
        r->has_retailGeneratorId = b_i32(pr, DS_NAME_retailGeneratorId, &r->retailGeneratorId);
        r->has_retailServerId = b_i32(pr, DS_NAME_retailServerId, &r->retailServerId);
        r->has_retailerId = b_i32(pr, DS_NAME_retailerId, &r->retailerId);
        r->has_retailPointId = b_i64(pr, DS_NAME_retailPointId, &r->retailPointId);
        ic->productRetailer = r;
    }
    *out = ic;
    return true;
}

static dosipas_issuing_detail_t *bind_issuing(dosipas_arena_t *a, const dosipas_value_t *seq) {
    if (!seq) return NULL;
    dosipas_issuing_detail_t *d = ALLOC(a, dosipas_issuing_detail_t);
    if (!d) return NULL;
    d->value = seq;
    d->has_securityProviderNum = b_i32(seq, DS_NAME_securityProviderNum, &d->securityProviderNum);
    d->securityProviderIA5 = b_str(seq, DS_NAME_securityProviderIA5);
    d->has_issuerNum = b_i32(seq, DS_NAME_issuerNum, &d->issuerNum);
    d->issuerIA5 = b_str(seq, DS_NAME_issuerIA5);
    b_i32(seq, DS_NAME_issuingYear, &d->issuingYear);
    b_i32(seq, DS_NAME_issuingDay, &d->issuingDay);
    d->has_issuingTime = b_i32(seq, DS_NAME_issuingTime, &d->issuingTime);
    d->issuerName = b_str(seq, DS_NAME_issuerName);
    b_bool(seq, DS_NAME_specimen, &d->specimen);
    b_bool(seq, DS_NAME_securePaperTicket, &d->securePaperTicket);
    b_bool(seq, DS_NAME_activated, &d->activated);
    d->currency = b_str(seq, DS_NAME_currency);
    d->currencyFract = 2;
    b_i32(seq, DS_NAME_currencyFract, &d->currencyFract);
    d->issuerPNR = b_str(seq, DS_NAME_issuerPNR);
    d->has_issuedOnTrainNum = b_i64(seq, DS_NAME_issuedOnTrainNum, &d->issuedOnTrainNum);
    d->issuedOnTrainIA5 = b_str(seq, DS_NAME_issuedOnTrainIA5);
    d->has_issuedOnLine = b_i64(seq, DS_NAME_issuedOnLine, &d->issuedOnLine);
    const dosipas_value_t *pos = M(seq, pointOfSale);
    if (pos && !(d->pointOfSale = bind_geo(a, pos))) return NULL;
    const dosipas_value_t *ext = M(seq, extension);
    if (ext && !(d->extension = bind_extension(a, ext))) return NULL;
    dosipas_intercode_issuing_t *ic = NULL;
    if (d->extension && !bind_intercode_issuing(a, d->extension, &ic)) return NULL;
    d->intercodeIssuing = ic;
    return d;
}

static dosipas_traveler_detail_t *bind_traveler_detail(dosipas_arena_t *a, const dosipas_value_t *seq) {
    if (!seq) return NULL;
    dosipas_traveler_detail_t *td = ALLOC(a, dosipas_traveler_detail_t);
    if (!td) return NULL;
    td->value = seq;
    td->preferredLanguage = b_str(seq, DS_NAME_preferredLanguage);
    td->groupName = b_str(seq, DS_NAME_groupName);
    const dosipas_value_t *list = b_list(seq, DS_NAME_traveler, &td->traveler_count);
    if (list && td->traveler_count) {
        td->traveler = ALLOC_N(a, dosipas_traveler_t, td->traveler_count);
        if (!td->traveler) return NULL;
        size_t i = 0;
        for (const dosipas_value_t *tv = list->u.child; tv && i < td->traveler_count; tv = tv->next, i++) {
            dosipas_traveler_t *t = &td->traveler[i];
            t->value = tv;
            t->firstName = b_str(tv, DS_NAME_firstName);
            t->secondName = b_str(tv, DS_NAME_secondName);
            t->lastName = b_str(tv, DS_NAME_lastName);
            t->idCard = b_str(tv, DS_NAME_idCard);
            t->passportId = b_str(tv, DS_NAME_passportId);
            t->title = b_str(tv, DS_NAME_title);
            t->gender = b_enum(tv, DS_NAME_gender);
            t->customerIdIA5 = b_str(tv, DS_NAME_customerIdIA5);
            t->has_customerIdNum = b_i64(tv, DS_NAME_customerIdNum, &t->customerIdNum);
            t->has_yearOfBirth = b_i32(tv, DS_NAME_yearOfBirth, &t->yearOfBirth);
            t->has_monthOfBirth = b_i32(tv, DS_NAME_monthOfBirth, &t->monthOfBirth);
            t->has_dayOfBirth = b_i32(tv, DS_NAME_dayOfBirth, &t->dayOfBirth);
            t->has_dayOfBirthInMonth = b_i32(tv, DS_NAME_dayOfBirthInMonth, &t->dayOfBirthInMonth);
            t->has_ticketHolder = b_bool(tv, DS_NAME_ticketHolder, &t->ticketHolder);
            t->passengerType = b_enum(tv, DS_NAME_passengerType);
            t->has_passengerWithReducedMobility =
                b_bool(tv, DS_NAME_passengerWithReducedMobility, &t->passengerWithReducedMobility);
            t->has_countryOfResidence = b_i32(tv, DS_NAME_countryOfResidence, &t->countryOfResidence);
            t->has_countryOfPassport = b_i32(tv, DS_NAME_countryOfPassport, &t->countryOfPassport);
            t->has_countryOfIdCard = b_i32(tv, DS_NAME_countryOfIdCard, &t->countryOfIdCard);
            const dosipas_value_t *sl = b_list(tv, DS_NAME_status, &t->status_count);
            if (sl && t->status_count) {
                t->status = ALLOC_N(a, dosipas_customer_status_t, t->status_count);
                if (!t->status) return NULL;
                size_t k = 0;
                for (const dosipas_value_t *sv = sl->u.child; sv && k < t->status_count; sv = sv->next, k++) {
                    dosipas_customer_status_t *s = &t->status[k];
                    s->has_statusProviderNum = b_i32(sv, DS_NAME_statusProviderNum, &s->statusProviderNum);
                    s->statusProviderIA5 = b_str(sv, DS_NAME_statusProviderIA5);
                    s->has_customerStatus = b_i64(sv, DS_NAME_customerStatus, &s->customerStatus);
                    s->customerStatusDescr = b_str(sv, DS_NAME_customerStatusDescr);
                }
            }
        }
    }
    return td;
}

static dosipas_control_detail_t *bind_control(dosipas_arena_t *a, const dosipas_value_t *seq) {
    if (!seq) return NULL;
    dosipas_control_detail_t *c = ALLOC(a, dosipas_control_detail_t);
    if (!c) return NULL;
    c->value = seq;
    const dosipas_value_t *cl = b_list(seq, DS_NAME_identificationByCardReference, &c->identificationByCardReference_count);
    if (cl && c->identificationByCardReference_count) {
        c->identificationByCardReference = ALLOC_N(a, dosipas_card_reference_t, c->identificationByCardReference_count);
        if (!c->identificationByCardReference) return NULL;
        size_t i = 0;
        for (const dosipas_value_t *cv = cl->u.child; cv && i < c->identificationByCardReference_count; cv = cv->next, i++) {
            dosipas_card_reference_t *r = &c->identificationByCardReference[i];
            r->has_trailingCardIdNum = b_i64(cv, DS_NAME_trailingCardIdNum, &r->trailingCardIdNum);
            r->trailingCardIdIA5 = b_str(cv, DS_NAME_trailingCardIdIA5);
            r->cardName = b_str(cv, DS_NAME_cardName);
            r->has_cardIdNum = b_i64(cv, DS_NAME_cardIdNum, &r->cardIdNum);
            r->cardIdIA5 = b_str(cv, DS_NAME_cardIdIA5);
            r->has_leadingCardIdNum = b_i64(cv, DS_NAME_leadingCardIdNum, &r->leadingCardIdNum);
            r->leadingCardIdIA5 = b_str(cv, DS_NAME_leadingCardIdIA5);
            r->has_cardType = b_i32(cv, DS_NAME_cardType, &r->cardType);
            r->cardTypeDescr = b_str(cv, DS_NAME_cardTypeDescr);
        }
    }
    b_bool(seq, DS_NAME_identificationByIdCard, &c->identificationByIdCard);
    b_bool(seq, DS_NAME_identificationByPassportId, &c->identificationByPassportId);
    c->has_identificationItem = b_i32(seq, DS_NAME_identificationItem, &c->identificationItem);
    b_bool(seq, DS_NAME_passportValidationRequired, &c->passportValidationRequired);
    b_bool(seq, DS_NAME_onlineValidationRequired, &c->onlineValidationRequired);
    c->has_randomDetailedValidationRequired =
        b_i32(seq, DS_NAME_randomDetailedValidationRequired, &c->randomDetailedValidationRequired);
    b_bool(seq, DS_NAME_ageCheckRequired, &c->ageCheckRequired);
    b_bool(seq, DS_NAME_reductionCardCheckRequired, &c->reductionCardCheckRequired);
    c->infoText = b_str(seq, DS_NAME_infoText);
    const dosipas_value_t *tl = b_list(seq, DS_NAME_includedTickets, &c->includedTickets_count);
    if (tl && c->includedTickets_count) {
        c->includedTickets = ALLOC_N(a, dosipas_ticket_link_t, c->includedTickets_count);
        if (!c->includedTickets) return NULL;
        size_t i = 0;
        for (const dosipas_value_t *tv = tl->u.child; tv && i < c->includedTickets_count; tv = tv->next, i++) {
            dosipas_ticket_link_t *l = &c->includedTickets[i];
            l->referenceIA5 = b_str(tv, DS_NAME_referenceIA5);
            l->has_referenceNum = b_i64(tv, DS_NAME_referenceNum, &l->referenceNum);
            l->issuerName = b_str(tv, DS_NAME_issuerName);
            l->issuerPNR = b_str(tv, DS_NAME_issuerPNR);
            l->has_productOwnerNum = b_i32(tv, DS_NAME_productOwnerNum, &l->productOwnerNum);
            l->productOwnerIA5 = b_str(tv, DS_NAME_productOwnerIA5);
            l->ticketType = b_enum(tv, DS_NAME_ticketType);
            l->linkMode = b_enum(tv, DS_NAME_linkMode);
        }
    }
    const dosipas_value_t *ext = M(seq, extension);
    if (ext && !(c->extension = bind_extension(a, ext))) return NULL;
    return c;
}

static dosipas_zone_t *bind_zone(dosipas_arena_t *a, const dosipas_value_t *seq) {
    dosipas_zone_t *z = ALLOC(a, dosipas_zone_t);
    if (!z) return NULL;
    z->has_carrierNum = b_i32(seq, DS_NAME_carrierNum, &z->carrierNum);
    z->carrierIA5 = b_str(seq, DS_NAME_carrierIA5);
    z->stationCodeTable = b_enum(seq, DS_NAME_stationCodeTable);
    z->has_entryStationNum = b_i64(seq, DS_NAME_entryStationNum, &z->entryStationNum);
    z->entryStationIA5 = b_str(seq, DS_NAME_entryStationIA5);
    z->has_terminatingStationNum = b_i64(seq, DS_NAME_terminatingStationNum, &z->terminatingStationNum);
    z->terminatingStationIA5 = b_str(seq, DS_NAME_terminatingStationIA5);
    z->has_city = b_i64(seq, DS_NAME_city, &z->city);
    if (!b_i64_list(a, seq, DS_NAME_zoneId, &z->zoneId_count, &z->zoneId)) return NULL;
    z->binaryZoneId = b_bytes(seq, DS_NAME_binaryZoneId);
    z->nutsCode = b_str(seq, DS_NAME_nutsCode);
    return z;
}

static dosipas_line_t *bind_line(dosipas_arena_t *a, const dosipas_value_t *seq) {
    dosipas_line_t *l = ALLOC(a, dosipas_line_t);
    if (!l) return NULL;
    l->has_carrierNum = b_i32(seq, DS_NAME_carrierNum, &l->carrierNum);
    l->carrierIA5 = b_str(seq, DS_NAME_carrierIA5);
    if (!b_i64_list(a, seq, DS_NAME_lineId, &l->lineId_count, &l->lineId)) return NULL;
    l->stationCodeTable = b_enum(seq, DS_NAME_stationCodeTable);
    l->has_entryStationNum = b_i64(seq, DS_NAME_entryStationNum, &l->entryStationNum);
    l->entryStationIA5 = b_str(seq, DS_NAME_entryStationIA5);
    l->has_terminatingStationNum = b_i64(seq, DS_NAME_terminatingStationNum, &l->terminatingStationNum);
    l->terminatingStationIA5 = b_str(seq, DS_NAME_terminatingStationIA5);
    l->has_city = b_i64(seq, DS_NAME_city, &l->city);
    return l;
}

static dosipas_train_link_t *bind_train_link(dosipas_arena_t *a, const dosipas_value_t *seq) {
    dosipas_train_link_t *t = ALLOC(a, dosipas_train_link_t);
    if (!t) return NULL;
    t->has_trainNum = b_i64(seq, DS_NAME_trainNum, &t->trainNum);
    t->trainIA5 = b_str(seq, DS_NAME_trainIA5);
    t->has_travelDate = b_i32(seq, DS_NAME_travelDate, &t->travelDate);
    t->has_departureTime = b_i32(seq, DS_NAME_departureTime, &t->departureTime);
    t->has_departureUTCOffset = b_i32(seq, DS_NAME_departureUTCOffset, &t->departureUTCOffset);
    t->has_fromStationNum = b_i64(seq, DS_NAME_fromStationNum, &t->fromStationNum);
    t->fromStationIA5 = b_str(seq, DS_NAME_fromStationIA5);
    t->has_toStationNum = b_i64(seq, DS_NAME_toStationNum, &t->toStationNum);
    t->toStationIA5 = b_str(seq, DS_NAME_toStationIA5);
    t->fromStationNameUTF8 = b_str(seq, DS_NAME_fromStationNameUTF8);
    t->toStationNameUTF8 = b_str(seq, DS_NAME_toStationNameUTF8);
    return t;
}

/* Depth-bounded by the generic tree, which is itself bounded by DOSIPAS_MAX_DEPTH. */
static bool bind_via_station_list(dosipas_arena_t *a, const dosipas_value_t *seq, uint16_t name, size_t *count,
                                  dosipas_via_station_t **out);

static bool bind_via_station(dosipas_arena_t *a, const dosipas_value_t *seq, dosipas_via_station_t *v) {
    v->value = seq;
    v->stationCodeTable = b_enum(seq, DS_NAME_stationCodeTable);
    v->has_stationNum = b_i64(seq, DS_NAME_stationNum, &v->stationNum);
    v->stationIA5 = b_str(seq, DS_NAME_stationIA5);
    if (!bind_via_station_list(a, seq, DS_NAME_alternativeRoutes, &v->alternativeRoutes_count, &v->alternativeRoutes))
        return false;
    if (!bind_via_station_list(a, seq, DS_NAME_route, &v->route_count, &v->route)) return false;
    v->has_border = b_bool(seq, DS_NAME_border, &v->border);
    if (!b_i32_list(a, seq, DS_NAME_carrierNum, &v->carrierNum_count, &v->carrierNum)) return false;
    if (!b_str_list(a, seq, DS_NAME_carrierIA5, &v->carrierIA5_count, &v->carrierIA5)) return false;
    v->has_seriesId = b_i64(seq, DS_NAME_seriesId, &v->seriesId);
    v->has_routeId = b_i64(seq, DS_NAME_routeId, &v->routeId);
    if (!b_i32_list(a, seq, DS_NAME_includedServiceBrands, &v->includedServiceBrands_count, &v->includedServiceBrands))
        return false;
    if (!b_i32_list(a, seq, DS_NAME_excludedServiceBrands, &v->excludedServiceBrands_count, &v->excludedServiceBrands))
        return false;
    return true;
}

static bool bind_via_station_list(dosipas_arena_t *a, const dosipas_value_t *seq, uint16_t name, size_t *count,
                                  dosipas_via_station_t **out) {
    const dosipas_value_t *l = b_list(seq, name, count);
    *out = NULL;
    if (!l || *count == 0) return true;
    dosipas_via_station_t *arr = ALLOC_N(a, dosipas_via_station_t, *count);
    if (!arr) return false;
    size_t i = 0;
    for (const dosipas_value_t *it = l->u.child; it && i < *count; it = it->next, i++) {
        if (it->kind != DOSIPAS_V_SEQUENCE) continue;
        if (!bind_via_station(a, it, &arr[i])) return false;
    }
    *out = arr;
    return true;
}

static dosipas_open_ticket_t *bind_open_ticket(dosipas_arena_t *a, const dosipas_value_t *seq) {
    dosipas_open_ticket_t *o = ALLOC(a, dosipas_open_ticket_t);
    if (!o) return NULL;
    o->value = seq;
    o->has_referenceNum = b_i64(seq, DS_NAME_referenceNum, &o->referenceNum);
    o->referenceIA5 = b_str(seq, DS_NAME_referenceIA5);
    o->has_productOwnerNum = b_i32(seq, DS_NAME_productOwnerNum, &o->productOwnerNum);
    o->productOwnerIA5 = b_str(seq, DS_NAME_productOwnerIA5);
    o->has_productIdNum = b_i32(seq, DS_NAME_productIdNum, &o->productIdNum);
    o->productIdIA5 = b_str(seq, DS_NAME_productIdIA5);
    o->has_extIssuerId = b_i64(seq, DS_NAME_extIssuerId, &o->extIssuerId);
    o->has_issuerAuthorizationId = b_i64(seq, DS_NAME_issuerAuthorizationId, &o->issuerAuthorizationId);
    b_bool(seq, DS_NAME_returnIncluded, &o->returnIncluded);
    o->stationCodeTable = b_enum(seq, DS_NAME_stationCodeTable);
    o->has_fromStationNum = b_i64(seq, DS_NAME_fromStationNum, &o->fromStationNum);
    o->fromStationIA5 = b_str(seq, DS_NAME_fromStationIA5);
    o->has_toStationNum = b_i64(seq, DS_NAME_toStationNum, &o->toStationNum);
    o->toStationIA5 = b_str(seq, DS_NAME_toStationIA5);
    o->fromStationNameUTF8 = b_str(seq, DS_NAME_fromStationNameUTF8);
    o->toStationNameUTF8 = b_str(seq, DS_NAME_toStationNameUTF8);
    o->validRegionDesc = b_str(seq, DS_NAME_validRegionDesc);
    const dosipas_value_t *vr = b_list(seq, DS_NAME_validRegion, &o->validRegion_count);
    if (vr && o->validRegion_count) {
        o->validRegion = ALLOC_N(a, dosipas_valid_region_t, o->validRegion_count);
        if (!o->validRegion) return NULL;
        size_t i = 0;
        for (const dosipas_value_t *cv = vr->u.child; cv && i < o->validRegion_count; cv = cv->next, i++) {
            dosipas_valid_region_t *r = &o->validRegion[i];
            if (cv->kind != DOSIPAS_V_CHOICE) continue;
            r->key = dosipas_value_choice_key(cv);
            r->value = cv->u.child;
            if (!r->key || !r->value || r->value->kind != DOSIPAS_V_SEQUENCE) continue;
            if (strcmp(r->key, "zones") == 0) {
                if (!(r->zones = bind_zone(a, r->value))) return NULL;
            } else if (strcmp(r->key, "lines") == 0) {
                if (!(r->lines = bind_line(a, r->value))) return NULL;
            } else if (strcmp(r->key, "viaStations") == 0) {
                dosipas_via_station_t *vs = ALLOC(a, dosipas_via_station_t);
                if (!vs || !bind_via_station(a, r->value, vs)) return NULL;
                r->viaStations = vs;
            } else if (strcmp(r->key, "trainLink") == 0) {
                if (!(r->trainLink = bind_train_link(a, r->value))) return NULL;
            }
        }
    }
    o->returnDescription = M(seq, returnDescription);
    o->has_validFromDay = b_i32(seq, DS_NAME_validFromDay, &o->validFromDay);
    o->has_validFromTime = b_i32(seq, DS_NAME_validFromTime, &o->validFromTime);
    o->has_validFromUTCOffset = b_i32(seq, DS_NAME_validFromUTCOffset, &o->validFromUTCOffset);
    o->has_validUntilDay = b_i32(seq, DS_NAME_validUntilDay, &o->validUntilDay);
    o->has_validUntilTime = b_i32(seq, DS_NAME_validUntilTime, &o->validUntilTime);
    o->has_validUntilUTCOffset = b_i32(seq, DS_NAME_validUntilUTCOffset, &o->validUntilUTCOffset);
    if (!b_i32_list(a, seq, DS_NAME_activatedDay, &o->activatedDay_count, &o->activatedDay)) return NULL;
    o->classCode = b_enum(seq, DS_NAME_classCode);
    o->serviceLevel = b_str(seq, DS_NAME_serviceLevel);
    if (!b_i32_list(a, seq, DS_NAME_carrierNum, &o->carrierNum_count, &o->carrierNum)) return NULL;
    if (!b_str_list(a, seq, DS_NAME_carrierIA5, &o->carrierIA5_count, &o->carrierIA5)) return NULL;
    if (!b_i32_list(a, seq, DS_NAME_includedServiceBrands, &o->includedServiceBrands_count, &o->includedServiceBrands))
        return NULL;
    if (!b_i32_list(a, seq, DS_NAME_excludedServiceBrands, &o->excludedServiceBrands_count, &o->excludedServiceBrands))
        return NULL;
    const dosipas_value_t *tl = b_list(seq, DS_NAME_tariffs, &o->tariffs_count);
    if (tl && o->tariffs_count) {
        o->tariffs = ALLOC_N(a, const dosipas_value_t *, o->tariffs_count);
        if (!o->tariffs) return NULL;
        size_t i = 0;
        for (const dosipas_value_t *tv = tl->u.child; tv && i < o->tariffs_count; tv = tv->next) o->tariffs[i++] = tv;
    }
    o->has_price = b_i64(seq, DS_NAME_price, &o->price);
    o->infoText = b_str(seq, DS_NAME_infoText);
    return o;
}

static dosipas_rail_ticket_t *bind_rail_ticket(dosipas_arena_t *a, const dosipas_value_t *root, int version) {
    dosipas_rail_ticket_t *rt = ALLOC(a, dosipas_rail_ticket_t);
    if (!rt) return NULL;
    rt->value = root;
    rt->fcb_version = version;
    const dosipas_value_t *iss = M(root, issuingDetail);
    if (iss && !(rt->issuingDetail = bind_issuing(a, iss))) return NULL;
    const dosipas_value_t *td = M(root, travelerDetail);
    if (td && !(rt->travelerDetail = bind_traveler_detail(a, td))) return NULL;
    const dosipas_value_t *docs = b_list(root, DS_NAME_transportDocument, &rt->transportDocument_count);
    if (docs && rt->transportDocument_count) {
        rt->transportDocument = ALLOC_N(a, dosipas_transport_document_t, rt->transportDocument_count);
        if (!rt->transportDocument) return NULL;
        size_t i = 0;
        for (const dosipas_value_t *dv = docs->u.child; dv && i < rt->transportDocument_count; dv = dv->next, i++) {
            dosipas_transport_document_t *d = &rt->transportDocument[i];
            d->token = M(dv, token);
            const dosipas_value_t *tk = M(dv, ticket);
            if (tk && tk->kind == DOSIPAS_V_CHOICE) {
                d->ticket_key = dosipas_value_choice_key(tk);
                d->ticket_value = tk->u.child;
                if (d->ticket_key && d->ticket_value && d->ticket_value->kind == DOSIPAS_V_SEQUENCE &&
                    strcmp(d->ticket_key, "openTicket") == 0) {
                    if (!(d->openTicket = bind_open_ticket(a, d->ticket_value))) return NULL;
                }
            }
        }
    }
    const dosipas_value_t *cd = M(root, controlDetail);
    if (cd && !(rt->controlDetail = bind_control(a, cd))) return NULL;
    return rt;
}

/* ------------------------------------------------------------------------- */
/* Level 2 dynamic data                                                      */
/* ------------------------------------------------------------------------- */

static bool bind_ext_list(dosipas_arena_t *a, const dosipas_value_t *seq, uint16_t name, size_t *count,
                          dosipas_extension_t **out) {
    const dosipas_value_t *l = b_list(seq, name, count);
    *out = NULL;
    if (!l || *count == 0) return true;
    dosipas_extension_t *arr = ALLOC_N(a, dosipas_extension_t, *count);
    if (!arr) return false;
    size_t i = 0;
    for (const dosipas_value_t *it = l->u.child; it && i < *count; it = it->next, i++) {
        arr[i].extensionId = b_str(it, DS_NAME_extensionId);
        arr[i].extensionData = b_bytes(it, DS_NAME_extensionData);
    }
    *out = arr;
    return true;
}

static dosipas_dynamic_content_t *bind_fdc1(dosipas_arena_t *a, const dosipas_value_t *v) {
    dosipas_dynamic_content_t *d = ALLOC(a, dosipas_dynamic_content_t);
    if (!d) return NULL;
    d->value = v;
    d->dynamicContentMobileAppId = b_str(v, DS_NAME_dynamicContentMobileAppId);
    const dosipas_value_t *ts = M(v, dynamicContentTimeStamp);
    if (ts) {
        dosipas_time_stamp_t *t = ALLOC(a, dosipas_time_stamp_t);
        if (!t) return NULL;
        b_i32(ts, DS_NAME_day, &t->day);
        b_i32(ts, DS_NAME_time, &t->time);
        d->dynamicContentTimeStamp = t;
    }
    const dosipas_value_t *geo = M(v, dynamicContentGeoCoordinate);
    if (geo && !(d->dynamicContentGeoCoordinate = bind_geo(a, geo))) return NULL;
    if (!bind_ext_list(a, v, DS_NAME_dynamicContentResponseToChallenge, &d->dynamicContentResponseToChallenge_count,
                       &d->dynamicContentResponseToChallenge))
        return NULL;
    const dosipas_value_t *ext = M(v, dynamicContentExtension);
    if (ext && !(d->dynamicContentExtension = bind_extension(a, ext))) return NULL;
    return d;
}

static dosipas_intercode_dynamic_t *bind_intercode_dynamic(dosipas_arena_t *a, const dosipas_value_t *v) {
    dosipas_intercode_dynamic_t *d = ALLOC(a, dosipas_intercode_dynamic_t);
    if (!d) return NULL;
    d->value = v;
    b_i32(v, DS_NAME_dynamicContentDay, &d->dynamicContentDay);
    d->has_dynamicContentTime = b_i32(v, DS_NAME_dynamicContentTime, &d->dynamicContentTime);
    d->has_dynamicContentUTCOffset = b_i32(v, DS_NAME_dynamicContentUTCOffset, &d->dynamicContentUTCOffset);
    d->has_dynamicContentDuration = b_i32(v, DS_NAME_dynamicContentDuration, &d->dynamicContentDuration);
    return d;
}

static dosipas_level2_data_t *bind_level2_data(dosipas_arena_t *a, const dosipas_value_t *seq) {
    dosipas_level2_data_t *l2 = ALLOC(a, dosipas_level2_data_t);
    if (!l2) return NULL;
    l2->dataFormat = b_str(seq, DS_NAME_dataFormat);
    l2->data = b_bytes(seq, DS_NAME_data);
    if (!l2->dataFormat || !l2->data.ptr) return l2;
    uint16_t root;
    if (strcmp(l2->dataFormat, "FDC1") == 0) root = DS_ROOT_DYNAMIC_CONTENT_V1;
    else if (ds_is_intercode_dynamic_format(l2->dataFormat)) root = DS_ROOT_INTERCODE_DYNAMIC;
    else return l2;
    dosipas_value_t *v = NULL;
    if (!nested_decode(a, l2->data.ptr, l2->data.len, root, &v, &l2->decode_error, &l2->decode_error_bit)) return NULL;
    if (!v) return l2;
    if (root == DS_ROOT_DYNAMIC_CONTENT_V1) {
        if (!(l2->fdc1 = bind_fdc1(a, v))) return NULL;
    } else {
        if (!(l2->intercode = bind_intercode_dynamic(a, v))) return NULL;
    }
    return l2;
}

/* ------------------------------------------------------------------------- */
/* Header                                                                    */
/* ------------------------------------------------------------------------- */

static bool bind_level1(dosipas_arena_t *a, const dosipas_value_t *seq, dosipas_level1_data_t *l1) {
    l1->bit_offset = seq->bit_offset;
    l1->bit_length = seq->bit_length;
    l1->has_securityProviderNum = b_i32(seq, DS_NAME_securityProviderNum, &l1->securityProviderNum);
    l1->securityProviderIA5 = b_str(seq, DS_NAME_securityProviderIA5);
    l1->has_keyId = b_i32(seq, DS_NAME_keyId, &l1->keyId);
    l1->level1KeyAlg = b_str(seq, DS_NAME_level1KeyAlg);
    l1->level2KeyAlg = b_str(seq, DS_NAME_level2KeyAlg);
    l1->level1SigningAlg = b_str(seq, DS_NAME_level1SigningAlg);
    l1->level2SigningAlg = b_str(seq, DS_NAME_level2SigningAlg);
    l1->level2PublicKey = b_bytes(seq, DS_NAME_level2PublicKey);
    l1->has_endOfValidityYear = b_i32(seq, DS_NAME_endOfValidityYear, &l1->endOfValidityYear);
    l1->has_endOfValidityDay = b_i32(seq, DS_NAME_endOfValidityDay, &l1->endOfValidityDay);
    l1->has_endOfValidityTime = b_i32(seq, DS_NAME_endOfValidityTime, &l1->endOfValidityTime);
    l1->has_validityDuration = b_i32(seq, DS_NAME_validityDuration, &l1->validityDuration);

    const dosipas_value_t *ds = b_list(seq, DS_NAME_dataSequence, &l1->dataSequence_count);
    if (!ds || l1->dataSequence_count == 0) return true;
    l1->dataSequence = ALLOC_N(a, dosipas_data_entry_t, l1->dataSequence_count);
    if (!l1->dataSequence) return false;
    size_t i = 0;
    for (const dosipas_value_t *ev = ds->u.child; ev && i < l1->dataSequence_count; ev = ev->next, i++) {
        dosipas_data_entry_t *e = &l1->dataSequence[i];
        e->dataFormat = b_str(ev, DS_NAME_dataFormat);
        e->data = b_bytes(ev, DS_NAME_data);
        long fcb = ds_match_versioned(e->dataFormat, "FCB");
        if (fcb < 1 || fcb > 3 || !e->data.ptr) continue;
        uint16_t root = fcb == 1 ? DS_ROOT_RAIL_TICKET_V1 : fcb == 2 ? DS_ROOT_RAIL_TICKET_V2 : DS_ROOT_RAIL_TICKET_V3;
        dosipas_value_t *v = NULL;
        if (!nested_decode(a, e->data.ptr, e->data.len, root, &v, &e->decode_error, &e->decode_error_bit)) return false;
        if (!v) continue; /* dosipas-ts leaves `decoded` undefined when FCB decoding throws */
        dosipas_rail_ticket_t *rt = bind_rail_ticket(a, v, (int)fcb);
        if (!rt) return false; /* arena full while binding */
        e->decoded = rt;
    }
    return true;
}

dosipas_err_t dosipas_decode(const uint8_t *payload, size_t len, dosipas_arena_t *arena, dosipas_ticket_t **out) {
    dosipas_err_t err;
    uint32_t fb = 0;
    if (out) *out = NULL;
    if (!payload || !arena || !out || len == 0 || len > (0xffffffffu / 8u)) return DOSIPAS_ERR_ARG;
    arena->fail_code = DOSIPAS_OK;
    arena->fail_bit = 0;
    size_t mark = arena->used;

    /* Step 1: peek the header format (skip the level2Signature presence bit,
     * then an unconstrained IA5String) to choose the header schema. */
    ds_bits_t bits = {payload, 1, (uint32_t)len * 8u};
    uint16_t ia5_node = ds_fields[ds_nodes[DS_ROOT_HEADER_V1].aux].node;
    dosipas_value_t *fmt = ds_decode_root(&bits, ia5_node, arena, &err, &fb);
    if (!fmt) goto fail;
    long version = ds_match_versioned((const char *)fmt->u.data.ptr, "U");
    if (version < 0) {
        err = DOSIPAS_ERR_FORMAT;
        fb = 1;
        goto fail;
    }
    if (version != 1 && version != 2) {
        err = DOSIPAS_ERR_HEADER_VERSION;
        fb = 1;
        goto fail;
    }
    arena->used = mark;

    /* Step 2: decode the whole header. */
    bits.pos = 0;
    dosipas_value_t *hdr = ds_decode_root(&bits, version == 1 ? DS_ROOT_HEADER_V1 : DS_ROOT_HEADER_V2, arena, &err, &fb);
    if (!hdr) goto fail;

    dosipas_ticket_t *t = ALLOC(arena, dosipas_ticket_t);
    if (!t) {
        err = DOSIPAS_ERR_ARENA_FULL;
        goto fail;
    }
    t->header = hdr;
    t->header_version = (int)version;
    t->payload_len = len;
    t->format = b_str(hdr, DS_NAME_format);
    t->level2Signature = b_bytes(hdr, DS_NAME_level2Signature);

    const dosipas_value_t *l2s = M(hdr, level2SignedData);
    const dosipas_value_t *l1 = l2s ? M(l2s, level1Data) : NULL;
    if (!l2s || !l1) { /* cannot happen with a well-formed table: both are mandatory */
        err = DOSIPAS_ERR_ARG;
        goto fail;
    }
    t->level2SignedData_bit_offset = l2s->bit_offset;
    t->level2SignedData_bit_length = l2s->bit_length;
    t->level1Signature = b_bytes(l2s, DS_NAME_level1Signature);

    /* Steps 3-4: level1Data and the FCB records. */
    if (!bind_level1(arena, l1, &t->level1Data)) {
        err = DOSIPAS_ERR_ARENA_FULL;
        goto fail;
    }
    /* Step 5: level2Data with its dynamic content. */
    const dosipas_value_t *l2d = M(l2s, level2Data);
    if (l2d) {
        t->level2Data = bind_level2_data(arena, l2d);
        if (!t->level2Data) {
            err = DOSIPAS_ERR_ARENA_FULL;
            goto fail;
        }
    }
    *out = t;
    return DOSIPAS_OK;

fail:
    arena->used = mark;
    arena->fail_code = err;
    arena->fail_bit = fb;
    return err;
}

/* ------------------------------------------------------------------------- */
/* Signed bytes                                                              */
/* ------------------------------------------------------------------------- */

dosipas_err_t dosipas_extract_bits(const uint8_t *payload, size_t len, uint32_t bit_offset, uint32_t bit_length,
                                   uint8_t *out, size_t out_cap, size_t *out_len) {
    size_t n = ((size_t)bit_length + 7u) / 8u;
    if (out_len) *out_len = n;
    if (!payload || len > (0xffffffffu / 8u)) return DOSIPAS_ERR_ARG;
    if ((uint64_t)bit_offset + bit_length > (uint64_t)len * 8u) return DOSIPAS_ERR_ARG;
    if (n > out_cap) return DOSIPAS_ERR_SMALL_BUFFER;
    if (!out && n) return DOSIPAS_ERR_ARG;
    uint32_t full = bit_length / 8u, rest = bit_length % 8u;
    ds_bits_t b = {payload, bit_offset, bit_offset + bit_length};
    if (full && !ds_read_octets(&b, out, full)) return DOSIPAS_ERR_ARG;
    if (rest) {
        uint32_t v;
        if (!ds_read_bits(&b, rest, &v)) return DOSIPAS_ERR_ARG;
        out[full] = (uint8_t)(v << (8u - rest));
    }
    return DOSIPAS_OK;
}

dosipas_err_t dosipas_level1_signed_bytes(const uint8_t *payload, size_t len, const dosipas_ticket_t *t, uint8_t *out,
                                          size_t out_cap, size_t *out_len) {
    if (!t) return DOSIPAS_ERR_ARG;
    return dosipas_extract_bits(payload, len, t->level1Data.bit_offset, t->level1Data.bit_length, out, out_cap, out_len);
}

dosipas_err_t dosipas_level2_signed_bytes(const uint8_t *payload, size_t len, const dosipas_ticket_t *t, uint8_t *out,
                                          size_t out_cap, size_t *out_len) {
    if (!t) return DOSIPAS_ERR_ARG;
    return dosipas_extract_bits(payload, len, t->level2SignedData_bit_offset, t->level2SignedData_bit_length, out,
                                out_cap, out_len);
}

/* ------------------------------------------------------------------------- */
/* Time helpers                                                              */
/* ------------------------------------------------------------------------- */

/* Days from 1970-01-01 to year-month-day (proleptic Gregorian), Howard Hinnant's algorithm. */
static int64_t days_from_civil(int64_t y, unsigned m, unsigned d) {
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (153u * (m + (m > 2 ? (unsigned)-3 : 9u)) + 2u) / 5u + d - 1u;
    unsigned doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

int64_t dosipas_utc_from_day_of_year(int32_t year, int32_t day_of_year, int64_t minutes, int64_t seconds) {
    /* Date.UTC(year, 0, day) = Jan 1st of `year` plus (day - 1) days; day may overflow the year. */
    int64_t days = days_from_civil(year, 1, 1) + (int64_t)day_of_year - 1;
    return days * 86400 + minutes * 60 + seconds;
}

const dosipas_rail_ticket_t *dosipas_first_rail_ticket(const dosipas_ticket_t *t) {
    if (!t) return NULL;
    for (size_t i = 0; i < t->level1Data.dataSequence_count; i++) {
        if (t->level1Data.dataSequence[i].decoded) return t->level1Data.dataSequence[i].decoded;
    }
    return NULL;
}

bool dosipas_issuing_time(const dosipas_ticket_t *t, int64_t *out) {
    const dosipas_rail_ticket_t *rt = dosipas_first_rail_ticket(t);
    if (!rt || !rt->issuingDetail || !out) return false;
    const dosipas_issuing_detail_t *iss = rt->issuingDetail;
    *out = dosipas_utc_from_day_of_year(iss->issuingYear, iss->issuingDay, iss->has_issuingTime ? iss->issuingTime : 0, 0);
    return true;
}

bool dosipas_end_of_validity_time(const dosipas_ticket_t *t, int64_t *out) {
    if (!t || !out) return false;
    const dosipas_level1_data_t *l1 = &t->level1Data;
    if (!l1->has_endOfValidityYear || !l1->has_endOfValidityDay) return false;
    *out = dosipas_utc_from_day_of_year(l1->endOfValidityYear, l1->endOfValidityDay,
                                        l1->has_endOfValidityTime ? l1->endOfValidityTime : 0, 0);
    return true;
}

bool dosipas_dynamic_content_time(const dosipas_ticket_t *t, int64_t *out) {
    const dosipas_rail_ticket_t *rt = dosipas_first_rail_ticket(t);
    if (!t || !out || !rt || !rt->issuingDetail || !t->level2Data) return false;
    const dosipas_issuing_detail_t *iss = rt->issuingDetail;
    const dosipas_level2_data_t *l2 = t->level2Data;
    if (l2->fdc1) {
        const dosipas_time_stamp_t *ts = l2->fdc1->dynamicContentTimeStamp;
        if (!ts) return false;
        *out = dosipas_utc_from_day_of_year(iss->issuingYear, ts->day, 0, ts->time);
        return true;
    }
    if (l2->intercode) {
        const dosipas_intercode_dynamic_t *dd = l2->intercode;
        int64_t issuing = dosipas_utc_from_day_of_year(iss->issuingYear, iss->issuingDay, 0, 0);
        *out = issuing + (int64_t)dd->dynamicContentDay * 86400 +
               (dd->has_dynamicContentTime ? dd->dynamicContentTime : 0) +
               (int64_t)(dd->has_dynamicContentUTCOffset ? dd->dynamicContentUTCOffset : 0) * 15 * 60;
        return true;
    }
    return false;
}

bool dosipas_open_ticket_validity_window(const dosipas_open_ticket_t *o, const dosipas_issuing_detail_t *iss,
                                         int64_t *valid_from, int64_t *valid_until) {
    if (!o || !iss || !valid_from || !valid_until) return false;
    int64_t issuing = dosipas_utc_from_day_of_year(iss->issuingYear, iss->issuingDay, 0, 0);
    int64_t from_day = issuing + (int64_t)(o->has_validFromDay ? o->validFromDay : 0) * 86400;
    int64_t from_off = o->has_validFromUTCOffset ? o->validFromUTCOffset : 0;
    *valid_from = from_day + (int64_t)(o->has_validFromTime ? o->validFromTime : 0) * 60 - from_off * 15 * 60;
    int64_t until_day = from_day + (int64_t)(o->has_validUntilDay ? o->validUntilDay : 0) * 86400;
    int64_t until_off = o->has_validUntilUTCOffset ? o->validUntilUTCOffset : from_off;
    *valid_until = until_day + (int64_t)(o->has_validUntilTime ? o->validUntilTime : 1439) * 60 - until_off * 15 * 60;
    return true;
}
