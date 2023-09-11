#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdint.h>

static inline char hex_to_char(uint8_t h);

void string_to_hex(const char *str, uint8_t *hash, size_t len);

void hex_to_string(const uint8_t *hash, char *str, size_t len);

void ntoh_hex(uint8_t *hhash, const uint8_t *nhash, size_t len);

void hton_hex(uint8_t *nhash, const uint8_t *hhash, size_t len);

static inline char hex_to_char(uint8_t h) {
    if (h < 10) {
        return h + 48;
    } 
    return 97 + (h % 10);
}

static inline uint8_t char_to_hex(char c) {
    if (c >= 97) {
        return ((c - 97) + 10) & 0x0F;
    } 
    return (c - 48) & 0x0F;
}


void print_buf(const char *name, const uint8_t *buf, size_t len);

#endif
