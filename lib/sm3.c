#include "sm3.h"
#include "errs.h"

int do_sm3_digest(unsigned char *data, int datalen, unsigned char *hash)
{
    sm3_ctx_t sm3_ctx;

    sm3_init(&sm3_ctx);
	sm3_update(&sm3_ctx, data, datalen);
	sm3_final(&sm3_ctx, hash);

    return DIGEST_SUCC;
}