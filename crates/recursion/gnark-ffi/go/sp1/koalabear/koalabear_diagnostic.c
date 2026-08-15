//go:build diagnostic

#include <stdint.h>

#define KOALA_BEAR_MODULUS UINT64_C(0x7f000001)

typedef struct {
    uint64_t limb[4];
} extension_element;

static uint64_t add_mod(uint64_t left, uint64_t right) {
    return (left + right) % KOALA_BEAR_MODULUS;
}

static uint64_t mul_mod(uint64_t left, uint64_t right) {
    return (left * right) % KOALA_BEAR_MODULUS;
}

static uint64_t pow_mod(uint64_t value, uint64_t exponent) {
    uint64_t result = 1;
    while (exponent != 0) {
        if ((exponent & 1) != 0) {
            result = mul_mod(result, value);
        }
        value = mul_mod(value, value);
        exponent >>= 1;
    }
    return result;
}

static extension_element extension_mul(extension_element left, extension_element right) {
    uint64_t product[7] = {0};
    extension_element result = {{0}};
    for (uint32_t i = 0; i < 4; i++) {
        for (uint32_t j = 0; j < 4; j++) {
            product[i + j] = add_mod(product[i + j], mul_mod(left.limb[i], right.limb[j]));
        }
    }
    for (uint32_t i = 0; i < 4; i++) {
        result.limb[i] = product[i];
    }
    for (uint32_t i = 4; i < 7; i++) {
        result.limb[i - 4] = add_mod(result.limb[i - 4], mul_mod(3, product[i]));
    }
    return result;
}

static extension_element extension_pow(extension_element value, __uint128_t exponent) {
    extension_element result = {{1, 0, 0, 0}};
    while (exponent != 0) {
        if ((exponent & 1) != 0) {
            result = extension_mul(result, value);
        }
        value = extension_mul(value, value);
        exponent >>= 1;
    }
    return result;
}

uint32_t koalabearinv(uint32_t value) {
    return (uint32_t)pow_mod(value % KOALA_BEAR_MODULUS, KOALA_BEAR_MODULUS - 2);
}

uint32_t koalabearextinv(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t index) {
    const __uint128_t p = KOALA_BEAR_MODULUS;
    extension_element value = {{a % KOALA_BEAR_MODULUS,
                                b % KOALA_BEAR_MODULUS,
                                c % KOALA_BEAR_MODULUS,
                                d % KOALA_BEAR_MODULUS}};
    extension_element inverse = extension_pow(value, p * p * p * p - 2);
    return (uint32_t)inverse.limb[index];
}
