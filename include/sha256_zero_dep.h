#ifndef SHA256_ZERO_DEP_H
#define SHA256_ZERO_DEP_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  data[64];
    size_t   datalen;
} sha256_ctx_t;

void sha256_init(sha256_ctx_t *ctx);
void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx_t *ctx, uint8_t hash[32]);
void sha256_hex(const uint8_t *data, size_t len, char out_hex[65]);

#endif /* SHA256_ZERO_DEP_H */
