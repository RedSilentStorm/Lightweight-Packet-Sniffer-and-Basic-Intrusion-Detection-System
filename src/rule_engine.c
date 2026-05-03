#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "packet_headers.h"
#include "rule_engine.h"

static int equals_ignore_case(const char *a, const char *b) {
    unsigned char ca;
    unsigned char cb;

    if (a == NULL || b == NULL) {
        return 0;
    }

    while (*a != '\0' && *b != '\0') {
        ca = (unsigned char)*a;
        cb = (unsigned char)*b;
        if ((unsigned char)tolower(ca) != (unsigned char)tolower(cb)) {
            return 0;
        }
        a++;
        b++;
    }

    return *a == '\0' && *b == '\0';
}

static int parse_protocol_token(const char *token, uint8_t *out_protocol) {
    char *end = NULL;
    unsigned long parsed = 0;

    if (token == NULL || out_protocol == NULL || token[0] == '\0') {
        return 0;
    }

    if (equals_ignore_case(token, "any")) {
        *out_protocol = 0;
        return 1;
    }

    if (equals_ignore_case(token, "tcp")) {
        *out_protocol = IP_PROTOCOL_TCP;
        return 1;
    }

    if (equals_ignore_case(token, "udp")) {
        *out_protocol = IP_PROTOCOL_UDP;
        return 1;
    }

    if (equals_ignore_case(token, "icmp")) {
        *out_protocol = 1;
        return 1;
    }

    errno = 0;
    parsed = strtoul(token, &end, 10);
    if (errno != 0 || end == token || *end != '\0' || parsed > 255UL) {
        return 0;
    }

    *out_protocol = (uint8_t)parsed;
    return 1;
}

static int parse_port_token(const char *token, uint16_t *out_port) {
    char *end = NULL;
    unsigned long parsed = 0;

    if (token == NULL || out_port == NULL || token[0] == '\0') {
        return 0;
    }

    if (equals_ignore_case(token, "any")) {
        *out_port = 0;
        return 1;
    }

    errno = 0;
    parsed = strtoul(token, &end, 10);
    if (errno != 0 || end == token || *end != '\0' || parsed > 65535UL) {
        return 0;
    }

    *out_port = (uint16_t)parsed;
    return 1;
}

static int parse_threshold_token(const char *token, unsigned int *out_threshold) {
    char *end = NULL;
    unsigned long parsed = 0;

    if (token == NULL || out_threshold == NULL || token[0] == '\0') {
        return 0;
    }

    errno = 0;
    parsed = strtoul(token, &end, 10);
    if (errno != 0 || end == token || *end != '\0' || parsed == 0 || parsed > UINT_MAX) {
        return 0;
    }

    *out_threshold = (unsigned int)parsed;
    return 1;
}

void ids_rule_engine_init(struct ids_rule_engine *engine) {
    if (engine == NULL) {
        return;
    }

    memset(engine, 0, sizeof(*engine));
}

int ids_rule_engine_add(struct ids_rule_engine *engine, uint8_t protocol, uint16_t port, unsigned int threshold) {
    if (engine == NULL || threshold == 0 || engine->count >= IDS_MAX_RULES) {
        return 0;
    }

    engine->rules[engine->count].protocol = protocol;
    engine->rules[engine->count].port = port;
    engine->rules[engine->count].threshold = threshold;
    engine->count++;
    return 1;
}

int ids_rule_engine_add_from_spec(struct ids_rule_engine *engine, const char *spec) {
    const char *p1 = NULL;
    const char *p2 = NULL;
    size_t l1 = 0;
    size_t l2 = 0;
    size_t l3 = 0;
    char t1[16];
    char t2[16];
    char t3[16];
    uint8_t protocol = 0;
    uint16_t port = 0;
    unsigned int threshold = 0;

    if (engine == NULL || spec == NULL) {
        return 0;
    }

    p1 = strchr(spec, ':');
    if (p1 == NULL) {
        return 0;
    }

    p2 = strchr(p1 + 1, ':');
    if (p2 == NULL) {
        return 0;
    }

    l1 = (size_t)(p1 - spec);
    l2 = (size_t)(p2 - (p1 + 1));
    l3 = strlen(p2 + 1);

    if (l1 == 0 || l2 == 0 || l3 == 0 || l1 >= sizeof(t1) || l2 >= sizeof(t2) || l3 >= sizeof(t3)) {
        return 0;
    }

    memcpy(t1, spec, l1);
    t1[l1] = '\0';
    memcpy(t2, p1 + 1, l2);
    t2[l2] = '\0';
    memcpy(t3, p2 + 1, l3);
    t3[l3] = '\0';

    if (!parse_protocol_token(t1, &protocol)) {
        return 0;
    }

    if (!parse_port_token(t2, &port)) {
        return 0;
    }

    if (!parse_threshold_token(t3, &threshold)) {
        return 0;
    }

    return ids_rule_engine_add(engine, protocol, port, threshold);
}

int ids_rule_engine_match(const struct ids_rule_engine *engine, uint8_t protocol, uint16_t source_port, uint16_t destination_port) {
    size_t i = 0;
    int best_index = -1;
    int best_score = -1;

    if (engine == NULL) {
        return -1;
    }

    for (i = 0; i < engine->count; i++) {
        const struct ids_rule *rule = &engine->rules[i];
        int protocol_match = (rule->protocol == 0 || rule->protocol == protocol);
        int port_match = (rule->port == 0 || rule->port == source_port || rule->port == destination_port);
        int score = 0;

        if (!protocol_match || !port_match) {
            continue;
        }

        if (rule->protocol != 0) {
            score += 2;
        }

        if (rule->port != 0) {
            score += 1;
        }

        if (score > best_score) {
            best_score = score;
            best_index = (int)i;
        }
    }

    return best_index;
}
