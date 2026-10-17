/*
 * dosipas-c: decode DOSIPAS tickets (UIC barcodes with Intercode 6 extensions)
 * on microcontrollers and desktop hosts.
 *
 * Reference behaviour: dosipas-ts 4.1.0 (https://github.com/sysdevrun/dosipas-ts).
 * The decoder is a table-driven ASN.1 unaligned PER (UPER) reader; the tables
 * are generated from the dosipas-ts JSON schemas (see tools/gen_schema_tables.mjs).
 *
 * Memory model: everything the decoder produces lives in a caller-provided arena
 * (dosipas_arena_t). No malloc, no recursion deeper than DOSIPAS_MAX_DEPTH, no
 * references into the payload buffer after dosipas_decode() returns.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef DOSIPAS_H
#define DOSIPAS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DOSIPAS_VERSION "0.1.0"
#define DOSIPAS_REFERENCE_VERSION "dosipas-ts 4.1.0"

/* Maximum nesting depth of ASN.1 values accepted by the decoder. The deepest
 * legitimate path in UicRailTicketData is about 14 levels; recursive
 * ViaStationType routes add two per nesting. */
#ifndef DOSIPAS_MAX_DEPTH
#define DOSIPAS_MAX_DEPTH 32
#endif

/* Arena size that decodes every dosipas-ts fixture with more than 2x margin
 * (largest fixture peak: 6.3 KB, see README). */
#define DOSIPAS_RECOMMENDED_ARENA_SIZE (16 * 1024)

/* ------------------------------------------------------------------------- */
/* Errors                                                                    */
/* ------------------------------------------------------------------------- */

typedef enum dosipas_err {
    DOSIPAS_OK = 0,
    DOSIPAS_ERR_ARG,            /* NULL pointer, empty or oversized payload */
    DOSIPAS_ERR_TRUNCATED,      /* read past the end of the payload or of an open type */
    DOSIPAS_ERR_ARENA_FULL,     /* the arena is too small for this payload */
    DOSIPAS_ERR_DEPTH,          /* nesting deeper than DOSIPAS_MAX_DEPTH */
    DOSIPAS_ERR_LENGTH,         /* fragmented length determinant (>= 16384) or length beyond the data */
    DOSIPAS_ERR_INTEGER,        /* unconstrained INTEGER wider than 64 bits */
    DOSIPAS_ERR_ENUM,           /* extension enumeration index out of range */
    DOSIPAS_ERR_CHOICE,         /* extension alternative index out of range */
    DOSIPAS_ERR_OID,            /* malformed OBJECT IDENTIFIER */
    DOSIPAS_ERR_FORMAT,         /* header format is not "U<n>" */
    DOSIPAS_ERR_HEADER_VERSION, /* header format U<n> with an unsupported n (only 1 and 2) */
    DOSIPAS_ERR_SMALL_BUFFER,   /* an output buffer is too small */
    DOSIPAS_ERR_UNSUPPORTED,    /* feature not available (e.g. verification without mbedTLS) */
} dosipas_err_t;

const char *dosipas_strerror(dosipas_err_t err);

/* ------------------------------------------------------------------------- */
/* Arena                                                                     */
/* ------------------------------------------------------------------------- */

typedef struct dosipas_arena {
    uint8_t *base;
    size_t cap;
    size_t used;
    size_t peak;            /* high-water mark since dosipas_arena_init() */
    dosipas_err_t fail_code;/* diagnostics of the last decode: error code ... */
    uint32_t fail_bit;      /* ... and the payload bit offset where it happened */
} dosipas_arena_t;

void dosipas_arena_init(dosipas_arena_t *arena, void *buffer, size_t size);
/* Forget every allocation (keeps `peak`). Invalidates all tickets decoded into it. */
void dosipas_arena_reset(dosipas_arena_t *arena);
/* Zeroed, 8-byte aligned allocation. Returns NULL when the arena is full. */
void *dosipas_arena_alloc(dosipas_arena_t *arena, size_t size);

/* ------------------------------------------------------------------------- */
/* Generic decoded value tree                                                */
/* ------------------------------------------------------------------------- */

typedef enum dosipas_value_kind {
    DOSIPAS_V_BOOLEAN = 1,
    DOSIPAS_V_INTEGER,     /* u.i */
    DOSIPAS_V_ENUMERATED,  /* name via dosipas_value_enum_name() */
    DOSIPAS_V_BYTES,       /* OCTET STRING: u.data */
    DOSIPAS_V_OID,         /* dotted string: u.data (NUL-terminated) */
    DOSIPAS_V_STRING,      /* IA5String (unpacked, 1 byte/char) or UTF8String (bytes unchanged): u.data, NUL-terminated */
    DOSIPAS_V_CHOICE,      /* u.child is the chosen value, key via dosipas_value_choice_key() */
    DOSIPAS_V_SEQUENCE,    /* u.child is the first present member, linked by `next`; aux = member count */
    DOSIPAS_V_SEQUENCE_OF, /* u.child is the first item; aux = item count */
} dosipas_value_kind_t;

#define DOSIPAS_VF_DEFAULT 0x01   /* synthesized from a DEFAULT, occupies no bits */
#define DOSIPAS_VF_EXTENSION 0x02 /* decoded from an extension addition (open type) */
#define DOSIPAS_NO_FIELD 0xffffu

typedef struct dosipas_value {
    uint8_t kind;        /* dosipas_value_kind_t */
    uint8_t flags;       /* DOSIPAS_VF_* */
    uint16_t schema;     /* schema node index (internal) */
    uint16_t field;      /* schema field index when this value is a SEQUENCE member, else DOSIPAS_NO_FIELD */
    uint16_t aux;        /* ENUMERATED: value index; CHOICE: alternative index; SEQUENCE/SEQUENCE OF: child count */
    uint32_t bit_offset; /* first bit of this value in the payload */
    uint32_t bit_length; /* number of bits it occupies (0 for defaults) */
    struct dosipas_value *next; /* next sibling in the parent SEQUENCE / SEQUENCE OF */
    union {
        int64_t i;                                  /* INTEGER, BOOLEAN (0/1) */
        struct { const uint8_t *ptr; uint32_t len; } data; /* BYTES, OID, STRING (ptr is NUL-terminated) */
        struct dosipas_value *child;                /* CHOICE value, first SEQUENCE member, first item */
    } u;
} dosipas_value_t;

/* Member name of a SEQUENCE member, or NULL. */
const char *dosipas_value_name(const dosipas_value_t *v);
/* Find a SEQUENCE member by name (absent -> NULL). */
const dosipas_value_t *dosipas_value_field(const dosipas_value_t *seq, const char *name);
/* i-th item of a SEQUENCE OF (out of range -> NULL). */
const dosipas_value_t *dosipas_value_item(const dosipas_value_t *list, size_t index);
/* Name of an ENUMERATED value. */
const char *dosipas_value_enum_name(const dosipas_value_t *v);
/* Alternative name of a CHOICE value. */
const char *dosipas_value_choice_key(const dosipas_value_t *v);

/* Decode one UPER value of a known schema root (advanced use, used by tests).
 * `root` is one of the DS_ROOT_* constants from dosipas_schema_names.h. */
dosipas_err_t dosipas_decode_value(const uint8_t *data, size_t len, uint16_t root, dosipas_arena_t *arena,
                                   dosipas_value_t **out, uint32_t *fail_bit);

/* ------------------------------------------------------------------------- */
/* Typed ticket model (mirrors the dosipas-ts types)                         */
/* ------------------------------------------------------------------------- */

typedef struct dosipas_bytes {
    const uint8_t *ptr; /* NULL when absent */
    uint32_t len;
} dosipas_bytes_t;

typedef struct dosipas_extension {
    const char *extensionId;
    dosipas_bytes_t extensionData;
} dosipas_extension_t;

typedef struct dosipas_product_retailer {
    const char *retailChannel; /* enumeration name or NULL */
    bool has_retailGeneratorId; int32_t retailGeneratorId;
    bool has_retailServerId;    int32_t retailServerId;
    bool has_retailerId;        int32_t retailerId;
    bool has_retailPointId;     int64_t retailPointId;
} dosipas_product_retailer_t;

typedef struct dosipas_intercode_issuing {
    const char *extensionId; /* copied from the enclosing extension, like dosipas-ts */
    int32_t intercodeVersion;
    int32_t intercodeInstanciation;
    dosipas_bytes_t networkId; /* 3 bytes */
    const dosipas_product_retailer_t *productRetailer;
    const dosipas_value_t *value; /* generic tree */
} dosipas_intercode_issuing_t;

typedef struct dosipas_geo_coordinate {
    const char *geoUnit;             /* ENUMERATED names (NULL when absent) */
    const char *coordinateSystem;
    const char *hemisphereLongitude;
    const char *hemisphereLatitude;
    bool has_longitude; int64_t longitude;
    bool has_latitude;  int64_t latitude;
    const char *accuracy;
} dosipas_geo_coordinate_t;

typedef struct dosipas_issuing_detail {
    bool has_securityProviderNum; int32_t securityProviderNum;
    const char *securityProviderIA5;
    bool has_issuerNum; int32_t issuerNum;
    const char *issuerIA5;
    int32_t issuingYear;
    int32_t issuingDay;
    bool has_issuingTime; int32_t issuingTime; /* minutes since midnight */
    const char *issuerName;
    bool specimen;
    bool securePaperTicket;
    bool activated;
    const char *currency;   /* DEFAULT "EUR" */
    int32_t currencyFract;  /* DEFAULT 2 */
    const char *issuerPNR;
    bool has_issuedOnTrainNum; int64_t issuedOnTrainNum;
    const char *issuedOnTrainIA5;
    bool has_issuedOnLine; int64_t issuedOnLine;
    const dosipas_geo_coordinate_t *pointOfSale;
    const dosipas_extension_t *extension;
    const dosipas_intercode_issuing_t *intercodeIssuing; /* when extensionId matches _<RICS>II1 / +<CC>II1 */
    const dosipas_value_t *value;
} dosipas_issuing_detail_t;

typedef struct dosipas_customer_status {
    bool has_statusProviderNum; int32_t statusProviderNum;
    const char *statusProviderIA5;
    bool has_customerStatus; int64_t customerStatus;
    const char *customerStatusDescr;
} dosipas_customer_status_t;

typedef struct dosipas_traveler {
    const char *firstName;
    const char *secondName;
    const char *lastName;
    const char *idCard;
    const char *passportId;
    const char *title;
    const char *gender;        /* ENUMERATED name */
    const char *customerIdIA5;
    bool has_customerIdNum; int64_t customerIdNum;
    bool has_yearOfBirth; int32_t yearOfBirth;
    bool has_monthOfBirth; int32_t monthOfBirth;
    bool has_dayOfBirth; int32_t dayOfBirth;               /* FCB1: day of year */
    bool has_dayOfBirthInMonth; int32_t dayOfBirthInMonth; /* FCB2/FCB3 */
    bool has_ticketHolder; bool ticketHolder;
    const char *passengerType; /* ENUMERATED name */
    bool has_passengerWithReducedMobility; bool passengerWithReducedMobility;
    bool has_countryOfResidence; int32_t countryOfResidence;
    bool has_countryOfPassport; int32_t countryOfPassport;
    bool has_countryOfIdCard; int32_t countryOfIdCard;
    size_t status_count; dosipas_customer_status_t *status;
    const dosipas_value_t *value;
} dosipas_traveler_t;

typedef struct dosipas_traveler_detail {
    size_t traveler_count; dosipas_traveler_t *traveler;
    const char *preferredLanguage;
    const char *groupName;
    const dosipas_value_t *value;
} dosipas_traveler_detail_t;

typedef struct dosipas_card_reference {
    bool has_trailingCardIdNum; int64_t trailingCardIdNum;
    const char *trailingCardIdIA5;
    const char *cardName;
    bool has_cardIdNum; int64_t cardIdNum;
    const char *cardIdIA5;
    bool has_leadingCardIdNum; int64_t leadingCardIdNum;
    const char *leadingCardIdIA5;
    bool has_cardType; int32_t cardType; /* schema name is cardType (dosipas-ts types call it cardTypeNum) */
    const char *cardTypeDescr;
} dosipas_card_reference_t;

typedef struct dosipas_ticket_link {
    const char *referenceIA5;
    bool has_referenceNum; int64_t referenceNum;
    const char *issuerName;
    const char *issuerPNR;
    bool has_productOwnerNum; int32_t productOwnerNum;
    const char *productOwnerIA5;
    const char *ticketType; /* ENUMERATED name */
    const char *linkMode;   /* ENUMERATED name */
} dosipas_ticket_link_t;

typedef struct dosipas_control_detail {
    size_t identificationByCardReference_count; dosipas_card_reference_t *identificationByCardReference;
    bool identificationByIdCard;
    bool identificationByPassportId;
    bool has_identificationItem; int32_t identificationItem;
    bool passportValidationRequired;
    bool onlineValidationRequired;
    bool has_randomDetailedValidationRequired; int32_t randomDetailedValidationRequired;
    bool ageCheckRequired;
    bool reductionCardCheckRequired;
    const char *infoText;
    size_t includedTickets_count; dosipas_ticket_link_t *includedTickets;
    const dosipas_extension_t *extension;
    const dosipas_value_t *value;
} dosipas_control_detail_t;

typedef struct dosipas_zone {
    bool has_carrierNum; int32_t carrierNum;
    const char *carrierIA5;
    const char *stationCodeTable;
    bool has_entryStationNum; int64_t entryStationNum;
    const char *entryStationIA5;
    bool has_terminatingStationNum; int64_t terminatingStationNum;
    const char *terminatingStationIA5;
    bool has_city; int64_t city;
    size_t zoneId_count; int64_t *zoneId;
    dosipas_bytes_t binaryZoneId;
    const char *nutsCode;
} dosipas_zone_t;

typedef struct dosipas_line {
    bool has_carrierNum; int32_t carrierNum;
    const char *carrierIA5;
    size_t lineId_count; int64_t *lineId;
    const char *stationCodeTable;
    bool has_entryStationNum; int64_t entryStationNum;
    const char *entryStationIA5;
    bool has_terminatingStationNum; int64_t terminatingStationNum;
    const char *terminatingStationIA5;
    bool has_city; int64_t city;
} dosipas_line_t;

typedef struct dosipas_via_station {
    const char *stationCodeTable;
    bool has_stationNum; int64_t stationNum;
    const char *stationIA5;
    size_t alternativeRoutes_count; struct dosipas_via_station *alternativeRoutes;
    size_t route_count; struct dosipas_via_station *route;
    bool has_border; bool border;
    size_t carrierNum_count; int32_t *carrierNum;
    size_t carrierIA5_count; const char **carrierIA5;
    bool has_seriesId; int64_t seriesId;
    bool has_routeId; int64_t routeId;
    size_t includedServiceBrands_count; int32_t *includedServiceBrands;
    size_t excludedServiceBrands_count; int32_t *excludedServiceBrands;
    const dosipas_value_t *value;
} dosipas_via_station_t;

typedef struct dosipas_train_link {
    bool has_trainNum; int64_t trainNum;
    const char *trainIA5;
    bool has_travelDate; int32_t travelDate;
    bool has_departureTime; int32_t departureTime;
    bool has_departureUTCOffset; int32_t departureUTCOffset;
    bool has_fromStationNum; int64_t fromStationNum;
    const char *fromStationIA5;
    bool has_toStationNum; int64_t toStationNum;
    const char *toStationIA5;
    const char *fromStationNameUTF8;
    const char *toStationNameUTF8;
} dosipas_train_link_t;

typedef struct dosipas_valid_region {
    const char *key;                 /* "zones", "lines", "viaStations", "trainLink", "polygone" */
    const dosipas_value_t *value;    /* generic value of the alternative */
    const dosipas_zone_t *zones;
    const dosipas_line_t *lines;
    const dosipas_via_station_t *viaStations;
    const dosipas_train_link_t *trainLink;
} dosipas_valid_region_t;

typedef struct dosipas_open_ticket {
    bool has_referenceNum; int64_t referenceNum;
    const char *referenceIA5;
    bool has_productOwnerNum; int32_t productOwnerNum;
    const char *productOwnerIA5;
    bool has_productIdNum; int32_t productIdNum;
    const char *productIdIA5;
    bool has_extIssuerId; int64_t extIssuerId;
    bool has_issuerAuthorizationId; int64_t issuerAuthorizationId;
    bool returnIncluded;
    const char *stationCodeTable;   /* ENUMERATED name (DEFAULT present) */
    bool has_fromStationNum; int64_t fromStationNum;
    const char *fromStationIA5;
    bool has_toStationNum; int64_t toStationNum;
    const char *toStationIA5;
    const char *fromStationNameUTF8;
    const char *toStationNameUTF8;
    const char *validRegionDesc;
    size_t validRegion_count; dosipas_valid_region_t *validRegion;
    const dosipas_value_t *returnDescription;
    bool has_validFromDay; int32_t validFromDay;
    bool has_validFromTime; int32_t validFromTime;
    bool has_validFromUTCOffset; int32_t validFromUTCOffset;
    bool has_validUntilDay; int32_t validUntilDay;
    bool has_validUntilTime; int32_t validUntilTime;
    bool has_validUntilUTCOffset; int32_t validUntilUTCOffset;
    size_t activatedDay_count; int32_t *activatedDay;
    const char *classCode;    /* ENUMERATED name */
    const char *serviceLevel;
    size_t carrierNum_count; int32_t *carrierNum;
    size_t carrierIA5_count; const char **carrierIA5;
    size_t includedServiceBrands_count; int32_t *includedServiceBrands;
    size_t excludedServiceBrands_count; int32_t *excludedServiceBrands;
    size_t tariffs_count; const dosipas_value_t **tariffs; /* generic TariffType values */
    bool has_price; int64_t price;
    const char *infoText;
    const dosipas_value_t *value; /* the full generic OpenTicketData */
} dosipas_open_ticket_t;

typedef struct dosipas_transport_document {
    const dosipas_value_t *token;       /* generic TokenType or NULL */
    const char *ticket_key;             /* CHOICE alternative name, e.g. "openTicket" */
    const dosipas_value_t *ticket_value;/* generic value of the alternative */
    const dosipas_open_ticket_t *openTicket; /* typed view when ticket_key == "openTicket" */
} dosipas_transport_document_t;

typedef struct dosipas_rail_ticket {
    int fcb_version; /* 1, 2 or 3 */
    const dosipas_issuing_detail_t *issuingDetail;
    const dosipas_traveler_detail_t *travelerDetail;
    size_t transportDocument_count; dosipas_transport_document_t *transportDocument;
    const dosipas_control_detail_t *controlDetail;
    const dosipas_value_t *value; /* generic UicRailTicketData */
} dosipas_rail_ticket_t;

typedef struct dosipas_data_entry {
    const char *dataFormat;
    dosipas_bytes_t data;
    const dosipas_rail_ticket_t *decoded; /* FCB1/2/3 data that decoded successfully, else NULL */
    dosipas_err_t decode_error;           /* why `decoded` is NULL for an FCB entry (DOSIPAS_OK when not FCB) */
    uint32_t decode_error_bit;            /* bit offset inside `data` of the failure */
} dosipas_data_entry_t;

typedef struct dosipas_level1_data {
    bool has_securityProviderNum; int32_t securityProviderNum;
    const char *securityProviderIA5;
    bool has_keyId; int32_t keyId;
    size_t dataSequence_count; dosipas_data_entry_t *dataSequence;
    const char *level1KeyAlg;     /* dotted OIDs or NULL */
    const char *level2KeyAlg;
    const char *level1SigningAlg;
    const char *level2SigningAlg;
    dosipas_bytes_t level2PublicKey;
    bool has_endOfValidityYear; int32_t endOfValidityYear; /* header v2 only */
    bool has_endOfValidityDay; int32_t endOfValidityDay;
    bool has_endOfValidityTime; int32_t endOfValidityTime;
    bool has_validityDuration; int32_t validityDuration;
    uint32_t bit_offset; /* bit range of the level1Data node in the payload: */
    uint32_t bit_length; /* exactly what level1Signature covers */
} dosipas_level1_data_t;

typedef struct dosipas_time_stamp {
    int32_t day;  /* day of year */
    int32_t time; /* seconds since midnight */
} dosipas_time_stamp_t;

typedef struct dosipas_dynamic_content {
    const char *dynamicContentMobileAppId;
    const dosipas_time_stamp_t *dynamicContentTimeStamp;
    const dosipas_geo_coordinate_t *dynamicContentGeoCoordinate;
    size_t dynamicContentResponseToChallenge_count; dosipas_extension_t *dynamicContentResponseToChallenge;
    const dosipas_extension_t *dynamicContentExtension;
    const dosipas_value_t *value;
} dosipas_dynamic_content_t;

typedef struct dosipas_intercode_dynamic {
    int32_t dynamicContentDay; /* DEFAULT 0 */
    bool has_dynamicContentTime; int32_t dynamicContentTime;           /* local seconds since midnight */
    bool has_dynamicContentUTCOffset; int32_t dynamicContentUTCOffset; /* quarter hours, local + offset = UTC */
    bool has_dynamicContentDuration; int32_t dynamicContentDuration;   /* seconds */
    const dosipas_value_t *value;
} dosipas_intercode_dynamic_t;

typedef struct dosipas_level2_data {
    const char *dataFormat;
    dosipas_bytes_t data;
    const dosipas_dynamic_content_t *fdc1;          /* when dataFormat == "FDC1" and it decoded */
    const dosipas_intercode_dynamic_t *intercode;   /* when dataFormat matches _<RICS>.ID1 and it decoded */
    dosipas_err_t decode_error;
    uint32_t decode_error_bit;
} dosipas_level2_data_t;

typedef struct dosipas_ticket {
    const char *format;  /* "U1" or "U2" */
    int header_version;  /* 1 or 2 */
    dosipas_level1_data_t level1Data;
    dosipas_bytes_t level1Signature;
    const dosipas_level2_data_t *level2Data; /* NULL when absent */
    dosipas_bytes_t level2Signature;
    uint32_t level2SignedData_bit_offset; /* bit range of the level2SignedData node: */
    uint32_t level2SignedData_bit_length; /* exactly what level2Signature covers */
    size_t payload_len;                   /* length of the payload this was decoded from */
    const dosipas_value_t *header;        /* generic UicBarcodeHeader tree */
} dosipas_ticket_t;

/* ------------------------------------------------------------------------- */
/* Decoding                                                                  */
/* ------------------------------------------------------------------------- */

/*
 * Decode a complete barcode payload.
 *
 * On success *out points to a ticket allocated in `arena` (valid until the arena
 * is reset). On failure the return value tells why; arena->fail_code and
 * arena->fail_bit repeat the error and the payload bit offset where decoding
 * stopped. Nested data (FCB records, Intercode extensions, dynamic content) is
 * decoded best-effort like dosipas-ts does: a failure there leaves the
 * corresponding `decoded` pointer NULL with a per-entry error, and
 * dosipas_decode() still returns DOSIPAS_OK. Only arena exhaustion is always a
 * hard failure.
 */
dosipas_err_t dosipas_decode(const uint8_t *payload, size_t len, dosipas_arena_t *arena, dosipas_ticket_t **out);

/* ------------------------------------------------------------------------- */
/* Signed bytes                                                              */
/* ------------------------------------------------------------------------- */

/*
 * Copy a bit range of the payload into `out`, shifted to start on a byte
 * boundary and zero-padded at the end (what dosipas-ts `extractTicket` returns
 * as signedBytes). *out_len receives the byte count, even when the buffer is
 * too small (DOSIPAS_ERR_SMALL_BUFFER).
 */
dosipas_err_t dosipas_extract_bits(const uint8_t *payload, size_t len, uint32_t bit_offset, uint32_t bit_length,
                                   uint8_t *out, size_t out_cap, size_t *out_len);
/* The bytes covered by level1Signature (the level1Data node). */
dosipas_err_t dosipas_level1_signed_bytes(const uint8_t *payload, size_t len, const dosipas_ticket_t *ticket,
                                          uint8_t *out, size_t out_cap, size_t *out_len);
/* The bytes covered by level2Signature (the level2SignedData node). */
dosipas_err_t dosipas_level2_signed_bytes(const uint8_t *payload, size_t len, const dosipas_ticket_t *ticket,
                                          uint8_t *out, size_t out_cap, size_t *out_len);

/* ------------------------------------------------------------------------- */
/* Time helpers (UTC, Unix seconds; never touch the device clock)            */
/* ------------------------------------------------------------------------- */

/* First dataSequence entry with decoded rail ticket data, or NULL. */
const dosipas_rail_ticket_t *dosipas_first_rail_ticket(const dosipas_ticket_t *ticket);
/* Equivalent of dosipas-ts getIssuingTime. */
bool dosipas_issuing_time(const dosipas_ticket_t *ticket, int64_t *unix_seconds);
/* Equivalent of getEndOfValidityTime (header v2 endOfValidity* fields only). */
bool dosipas_end_of_validity_time(const dosipas_ticket_t *ticket, int64_t *unix_seconds);
/* Equivalent of getDynamicContentTime (FDC1 and _<RICS>.ID1). */
bool dosipas_dynamic_content_time(const dosipas_ticket_t *ticket, int64_t *unix_seconds);
/* Equivalent of getOpenTicketValidityWindow. */
bool dosipas_open_ticket_validity_window(const dosipas_open_ticket_t *open_ticket,
                                         const dosipas_issuing_detail_t *issuing,
                                         int64_t *valid_from, int64_t *valid_until);
/* Date.UTC(year, 0, day_of_year, 0, minutes, seconds) in Unix seconds. */
int64_t dosipas_utc_from_day_of_year(int32_t year, int32_t day_of_year, int64_t minutes, int64_t seconds);

#ifdef __cplusplus
}
#endif

#endif /* DOSIPAS_H */
