#ifndef RULE_ENGINE_H
#define RULE_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#define IDS_MAX_RULES 32

/* protocol=0 means any protocol, port=0 means any source/destination port */
struct ids_rule {
    uint8_t protocol;
    uint16_t port;
    unsigned int threshold;
};

struct ids_rule_engine {
    struct ids_rule rules[IDS_MAX_RULES];
    size_t count;
};

void ids_rule_engine_init(struct ids_rule_engine *engine);
int ids_rule_engine_add(struct ids_rule_engine *engine, uint8_t protocol, uint16_t port, unsigned int threshold);
int ids_rule_engine_add_from_spec(struct ids_rule_engine *engine, const char *spec);
int ids_rule_engine_match(const struct ids_rule_engine *engine, uint8_t protocol, uint16_t source_port, uint16_t destination_port);

#endif
