#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "dax.h"

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(e,f,g)  (((e)&(f))^(~(e)&(g)))
#define MAJ(a,b,c) (((a)&(b))^((a)&(c))^((b)&(c)))
#define S0(a)      (ROR32(a,2)^ROR32(a,13)^ROR32(a,22))
#define S1(e)      (ROR32(e,6)^ROR32(e,11)^ROR32(e,25))
#define s0(x)      (ROR32(x,7)^ROR32(x,18)^((x)>>3))
#define s1(x)      (ROR32(x,17)^ROR32(x,19)^((x)>>10))

static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    uint32_t a,b,cc,d,e,f,g,h;
    int      i;

    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) | block[i*4+3];
    for (i = 16; i < 64; i++)
        w[i] = s1(w[i-2]) + w[i-7] + s0(w[i-15]) + w[i-16];

    a=state[0]; b=state[1]; cc=state[2]; d=state[3];
    e=state[4]; f=state[5]; g=state[6]; h=state[7];

    for (i = 0; i < 64; i++) {
        uint32_t t1 = h + S1(e) + CH(e,f,g) + K[i] + w[i];
        uint32_t t2 = S0(a) + MAJ(a,b,cc);
        h=g; g=f; f=e; e=d+t1;
        d=cc; cc=b; b=a; a=t1+t2;
    }

    state[0]+=a; state[1]+=b; state[2]+=cc; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g;  state[7]+=h;
}

static void sha256_raw(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t state[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    uint8_t  block[64];
    size_t   i;
    uint64_t bitlen = (uint64_t)len * 8;

    for (i = 0; i + 64 <= len; i += 64)
        sha256_transform(state, data + i);

    {
        size_t  rem = len - i;
        uint8_t pad[128];
        size_t  padlen;
        memset(pad, 0, sizeof(pad));
        memcpy(pad, data + i, rem);
        pad[rem] = 0x80;
        padlen = (rem < 56) ? 64 : 128;
        pad[padlen-8] = (uint8_t)(bitlen >> 56);
        pad[padlen-7] = (uint8_t)(bitlen >> 48);
        pad[padlen-6] = (uint8_t)(bitlen >> 40);
        pad[padlen-5] = (uint8_t)(bitlen >> 32);
        pad[padlen-4] = (uint8_t)(bitlen >> 24);
        pad[padlen-3] = (uint8_t)(bitlen >> 16);
        pad[padlen-2] = (uint8_t)(bitlen >>  8);
        pad[padlen-1] = (uint8_t)(bitlen      );
        sha256_transform(state, pad);
        if (padlen == 128) sha256_transform(state, pad + 64);
    }

    for (i = 0; i < 8; i++) {
        out[i*4+0] = (uint8_t)(state[i] >> 24);
        out[i*4+1] = (uint8_t)(state[i] >> 16);
        out[i*4+2] = (uint8_t)(state[i] >>  8);
        out[i*4+3] = (uint8_t)(state[i]      );
    }
    (void)block;
}

void dax_compute_sha256(dax_binary_t *bin) {
    uint8_t digest[32];
    int     i;

    if (!bin->data || bin->size == 0) return;

    sha256_raw(bin->data, bin->size, digest);

    for (i = 0; i < 32; i++)
        snprintf(bin->sha256 + i*2, 3, "%02x", digest[i]);
    bin->sha256[64] = '\0';
}
