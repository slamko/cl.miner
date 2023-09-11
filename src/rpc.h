#ifndef RPC_H
#define RPC_H

#include <stddef.h>
#include <curl/curl.h>
#include "miner.h"

CURLcode get_block_template(CURL *curl, struct submit_block *);

CURLcode submit_block(CURL *curl, struct submit_block *block);

#endif
