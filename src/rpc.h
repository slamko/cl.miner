#ifndef RPC_H
#define RPC_H

#include <stddef.h>
#include <curl/curl.h>
#include "miner.h"

CURLcode get_block_template(CURL *curl, struct submit_block *);

CURLcode submit_block(CURL *curl, struct submit_block *block);

CURLcode get_address_info(CURL *curl, const char *address, size_t *pk_script_len, uint8_t **pub_key_script);

#endif
