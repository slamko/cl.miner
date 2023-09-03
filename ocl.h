#ifndef OCL_H
#define OCL_H

#include <stdint.h>
#include <stddef.h>

int ocl_init(void);

int ocl_free(void);

int sha256(const uint8_t *data, uint8_t *out, size_t len);

void print_buf(const char *name, const uint8_t *buf, size_t len);

#endif
