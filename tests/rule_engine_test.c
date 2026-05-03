#include <stdio.h>
#include <string.h>

#include "packet_headers.h"
#include "rule_engine.h"

static int test_rule_parsing_and_matching(void) {
    struct ids_rule_engine engine;
    int index = -1;

    ids_rule_engine_init(&engine);

    if (!ids_rule_engine_add_from_spec(&engine, "tcp:80:5")) {
        return 0;
    }

    if (!ids_rule_engine_add_from_spec(&engine, "udp:any:3")) {
        return 0;
    }

    if (!ids_rule_engine_add_from_spec(&engine, "any:53:7")) {
        return 0;
    }

    if (engine.count != 3) {
        return 0;
    }

    index = ids_rule_engine_match(&engine, IP_PROTOCOL_TCP, 12345, 80);
    if (index != 0) {
        return 0;
    }

    index = ids_rule_engine_match(&engine, IP_PROTOCOL_UDP, 40000, 53);
    if (index != 1) {
        return 0;
    }

    index = ids_rule_engine_match(&engine, IP_PROTOCOL_UDP, 40000, 53);
    if (index != 1) {
        return 0;
    }

    index = ids_rule_engine_match(&engine, IP_PROTOCOL_TCP, 12345, 53);
    if (index != 2) {
        return 0;
    }

    index = ids_rule_engine_match(&engine, IP_PROTOCOL_TCP, 12345, 9999);
    if (index != -1) {
        return 0;
    }

    return 1;
}

static int test_rule_validation(void) {
    struct ids_rule_engine engine;

    ids_rule_engine_init(&engine);

    if (ids_rule_engine_add_from_spec(&engine, "broken") != 0) {
        return 0;
    }

    if (ids_rule_engine_add_from_spec(&engine, "tcp:70000:5") != 0) {
        return 0;
    }

    if (ids_rule_engine_add_from_spec(&engine, "udp:53:0") != 0) {
        return 0;
    }

    return 1;
}

int main(void) {
    if (!test_rule_parsing_and_matching()) {
        fprintf(stderr, "rule_engine_test: matching FAILED\n");
        return 1;
    }

    if (!test_rule_validation()) {
        fprintf(stderr, "rule_engine_test: validation FAILED\n");
        return 1;
    }

    printf("rule_engine_test: PASSED\n");
    return 0;
}
