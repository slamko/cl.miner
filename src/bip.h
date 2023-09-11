#ifndef BIP_H
#define BIP_H

#include <jansson.h>
#include "miner.h"
#include <stddef.h>

int build_merkle_root(transaction_list_t *tlist, size_t len, hash_t *merkle_root);

void nbits_to_target(uint32_t nbits, hash_t *target);

void hash_print(const char *name, hash_t *hash);

void block_serialize(const struct block_header *block, uint8_t raw[BLOCK_RAW_LEN]);

void block_pack(const struct block_header *block, uint8_t raw[BLOCK_RAW_LEN]);

int build_transaction_list(json_t *t_arr, transaction_list_t *tlist);

int build_merkle_root(transaction_list_t *tlist, size_t len, hash_t *merkle_root);

#endif
