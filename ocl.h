#ifndef OCL_H
#define OCL_H

#include <stdint.h>
#include <stddef.h>

int ocl_init(void);

int ocl_free(void);

int sha256(const uint8_t *data, size_t len);

#endif
