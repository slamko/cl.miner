
constant uint k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define CAT(x, y) x##y

#define rotr(base) \
    static inline uint CAT(rotr, base)(uint val) {                            \
        return (val >> (base)) | (val << (32 - (base))); \
    }

rotr(2)
rotr(6)
rotr(7)

rotr(11)
rotr(13)
rotr(22)
rotr(25)

rotr(17)
rotr(18)
rotr(19)

#define sigm0(x) (rotr7(x) ^ rotr18(x) ^ (x >> 3))
#define sigm1(x) (rotr17(x) ^ rotr19(x) ^ (x >> 10))

#define SUM0(x) (rotr2(x) ^ rotr13(x) ^ rotr22(x))
#define SUM1(x) (rotr6(x) ^ rotr11(x) ^ rotr25(x))

#define Ch(e, f, g) ((e & f) ^ ((~e) & g))
#define Maj(a, b, c) ((a & b) | (c & (a | b)))

void memcpy_char(__private unsigned char *dest, __global unsigned char *src, size_t len) {

    for (size_t i = 0; i < len; i++) {
        dest[i] = src[i];
    }
}
    
void memcpyui(__global unsigned char *dest, uint *src, size_t len) {

    for (size_t i = 0; i < len; i++) {
        for (int j = 0; j < 4; j++) {
            dest[(i * 4) + (3 - j)] = (src[i] >> (8 * j)) & 0xFF;
        }
    }
}

void memset_priv(__private uint *dest, uint val, size_t len) {

    for (size_t i = 0; i < len; i++) {
        dest[i] = val;
    }
}

void memcpy_priv(__private unsigned char *dest, __private uint *src, size_t len) {

    for (size_t i = 0; i < len; i++) {
        for (int j = 0; j < 4; j++) {
            dest[(i * 4) + (3 - j)] = (src[i] >> (8 * j)) & 0xFF;
        }
    }
}

__kernel void kern_sha256(__global __read_only const unsigned char *input,
                     unsigned long len,
                     __global __write_only unsigned char *output) {

    if (get_global_id(0) > 0) {
        return;
    }
    
    uint w[64];

    uint hi[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    size_t epochs = (len / 64) + (len % 64 ? 1 : 0);

    for (size_t epoch = 0; epoch < epochs; epoch++) {

    uint a = hi[0], b = hi[1], c = hi[2], d = hi[3], e = hi[4], f = hi[5], g = hi[6], h = hi[7];

    for (size_t i = 0; i < 16; i++) {
        w[i] = (((uint)input[(epoch * 64) + i * 4 + 0] & 0xFF) << 24) |
               (((uint)input[(epoch * 64) + i * 4 + 1] & 0xFF) << 16) |
               (((uint)input[(epoch * 64) + i * 4 + 2] & 0xFF) << 8) |
               (((uint)input[(epoch * 64) + i * 4 + 3] & 0xFF) );

    }

    for (size_t t = 16; t < 64; t++) {
        w[t] = sigm1(w[t-2]) + w[t - 7] + sigm0(w[t - 15]) + w[t - 16];
    }

    for (size_t t = 0; t < 64; t++) {
        uint t1 = h + SUM1(e) + Ch(e, f, g) + k[t] + w[t];
        uint t2 = SUM0(a) + Maj(a, b, c);
        // printf("W: %x : %x\n", w[t], ((uint)input[1]));

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    hi[0] += a;
    hi[1] += b;
    hi[2] += c;
    hi[3] += d;
    hi[4] += e;
    hi[5] += f;
    hi[6] += g;
    hi[7] += h;

    for (size_t i = 0; i < 8; i++) {
        // printf("Hi: %x\n", hi[i]);
    }

    }

    memcpyui(output, hi, 8);
}

void sha256(__global __read_only const unsigned char *input,
            unsigned long len,
            __global __write_only unsigned char *output) {

    uint w[64];

    uint hi[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    size_t epochs = (len / 64) + (len % 64 ? 1 : 0);

    for (size_t epoch = 0; epoch < epochs; epoch++) {

    uint a = hi[0], b = hi[1], c = hi[2], d = hi[3], e = hi[4], f = hi[5], g = hi[6], h = hi[7];

    for (size_t t = 0; t < 64; t++) {
        if (t < 16) { 
            w[t] = (((uint)input[(epoch * 64) + t * 4 + 0] & 0xFF) << 24) |
               (((uint)input[(epoch * 64) + t * 4 + 1] & 0xFF) << 16) |
               (((uint)input[(epoch * 64) + t * 4 + 2] & 0xFF) << 8) |
               (((uint)input[(epoch * 64) + t * 4 + 3] & 0xFF) );
        } else {

            w[t] = sigm1(w[t-2]) + w[t - 7] + sigm0(w[t - 15]) + w[t - 16];
        }

        uint t1 = h + SUM1(e) + Ch(e, f, g) + k[t] + w[t];
        uint t2 = SUM0(a) + Maj(a, b, c);
        // printf("W: %x : %x\n", w[t], ((uint)input[1]));

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    hi[0] += a;
    hi[1] += b;
    hi[2] += c;
    hi[3] += d;
    hi[4] += e;
    hi[5] += f;
    hi[6] += g;
    hi[7] += h;

    for (size_t i = 0; i < 8; i++) {
        // printf("Hi: %x\n", hi[i]);
    }

    }

    memcpyui(output, hi, 8);
}


void loc_sha256(__private const unsigned char *input,
                unsigned long len,
                __private uint *output) {
    uint w[64];
    size_t epochs = (len / 64) + (len % 64 ? 1 : 0);

    uint hi[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    for (size_t epoch = 0; epoch < epochs; epoch++) {

    uint a = hi[0], b = hi[1], c = hi[2], d = hi[3], e = hi[4], f = hi[5], g = hi[6], h = hi[7];

    for (size_t t = 0; t < 64; t++) {
        if (t < 16) { 
            w[t] = (((uint)input[(epoch * 64) + t * 4 + 0] & 0xFF) << 24) |
               (((uint)input[(epoch * 64) + t * 4 + 1] & 0xFF) << 16) |
               (((uint)input[(epoch * 64) + t * 4 + 2] & 0xFF) << 8) |
               (((uint)input[(epoch * 64) + t * 4 + 3] & 0xFF) );
        } else {

            w[t] = sigm1(w[t-2]) + w[t - 7] + sigm0(w[t - 15]) + w[t - 16];
        }

        uint t1 = h + SUM1(e) + Ch(e, f, g) + k[t] + w[t];
        uint t2 = SUM0(a) + Maj(a, b, c);
        // printf("W: %x : %x\n", w[t], ((uint)input[1]));

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    hi[0] += a;
    hi[1] += b;
    hi[2] += c;
    hi[3] += d;
    hi[4] += e;
    hi[5] += f;
    hi[6] += g;
    hi[7] += h;

    }

    for (size_t i = 0; i < 8; i++) {
        output[i] = hi[i];
    }
}

__kernel void mine256(__global unsigned char *block_raw, __global uint *target,
                      __global __read_write uint *nonce) {
    if (*nonce > 0) {
        return;
    }
    
    uint cur_nonce = get_global_id(0);
    
    __private unsigned char my_raw[128] = {0};
    memcpy_char(my_raw, block_raw, 128);

    for (size_t i = 0; i < 4; i++) {
        my_raw[(80 - 4) + i] = (cur_nonce >> 8 * i) & 0xFF;
    }

    __private unsigned char first_out[64] = {0};
    __private unsigned char out[32] = {0};
    __private uint hi[8] = {0};
    
    loc_sha256(my_raw, 128, hi);
    memcpy_priv(first_out, hi, 8);

    first_out[32] = 0x80;
    first_out[62] = 0x01; 

    memset_priv(hi, 0, sizeof hi);
    loc_sha256(first_out, 64, hi);

    // printf("Hash: %u : %lu : %x\n", get_global_id(0), cur_nonce, out[0]);

    for (size_t i = 7; i >= 0; i--) {
        uint big_hi =
            ((hi[i] & 0xFF) << 24) |
            ((hi[i] & 0xFF00) << 8) |
            ((hi[i] & 0xFF0000) >> 16) |
            ((hi[i] & 0xFF000000) >> 24);
                
        if (target[i] > big_hi) {
            /* printf("Hash: %x > %x. Nonce: %u\n", target[i] , big_hi, cur_nonce); */
            atomic_xchg(nonce, cur_nonce);
            return;
        }

        if (hi[i] > target[i]) {
            return;
        }
    }

    atomic_xchg(nonce, cur_nonce);
}

struct hash {
    unsigned char hash[32];
};

void memcpy_glob_to_priv(__private unsigned char *dest, __global unsigned char *src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dest[i] = src[i];
    }
}

__kernel void merkle_root_hash(__global __read_write struct hash *txid_list,
                               unsigned long len) {
    size_t x = get_global_id(0);
    size_t pair_len = len / 2;

    if (x >= pair_len) {
        return;
    }

    size_t mod = 2;

    for (size_t i = pair_len; i >= 1; i /= 2) {
        size_t cur_x = x * mod;
        __private unsigned char concat_hash[64];
        __global unsigned char *hasha = txid_list[cur_x].hash;
        __global unsigned char *hashb = hasha;
        
        if (cur_x + 1 < len) {
            hashb = txid_list[cur_x + 1].hash;
        }
        
        memcpy_glob_to_priv(concat_hash, hasha, sizeof (txid_list[cur_x].hash));
        memcpy_glob_to_priv(concat_hash + sizeof (concat_hash) / 2, hashb, sizeof (txid_list[cur_x + 1].hash));

        __private unsigned char first_out[64] = {0};
        __private unsigned char out[32] = {0};
        __private uint hi[8] = {0};
        
        loc_sha256(concat_hash, 128, hi);
        memcpyui(txid_list[cur_x].hash, hi, 8);
        
        first_out[32] = 0x80;
        first_out[62] = 0x01; 
        
        memset_priv(hi, 0, sizeof hi);
        loc_sha256(first_out, 64, hi);
        memcpy_priv(out, hi, 8);
        
        if (x > i) {
            break;
        }

        mod *= 2;
    }
}
