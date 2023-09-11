#include "util.h"
#include <stdint.h>
#include <stddef.h>
#include "miner.h"

void hton_hex(uint8_t *nhash, const uint8_t *hhash, size_t len) {
    for (size_t i = 0; i < len; i++) {
        nhash[len - i - 1] = hhash[i];
    }
}

void ntoh_hex(uint8_t *hhash, const uint8_t *nhash, size_t len) {
    for (size_t i = 0; i < len; i++) {
        hhash[len - i - 1] = nhash[i];
    }
}

void hex_to_string(const uint8_t *hash, char *str, size_t len) {
    for_range(i, 0, len) {
        uint8_t h = hash[i] >> 4;
        uint8_t l = hash[i] & 0x0F;

        str[i * 2] = hex_to_char(h);
        str[(i * 2) + 1] = hex_to_char(l);
    }
}

void string_to_hex(const char *str, uint8_t *hash, size_t len) {
    for_range(i, 0, len / 2) {
        hash[i] = (char_to_hex(str[i * 2]) << 4) | char_to_hex (str[(i * 2) + 1]); 
    }
}


void print_buf(const char *name, const uint8_t *buf, size_t len) {
    printf("Buf: %s\n", name);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    putc('\n', stdout);
}
