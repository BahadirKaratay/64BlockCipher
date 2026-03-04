#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* 4-bit S-Box: 16-entry bijective lookup table */
static const uint8_t SBOX[16] = {
    0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
    0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7
};

#define ROUNDS 4

static uint64_t rotl64(uint64_t x, int n) {
    return n ? (x << n) | (x >> (64 - n)) : x;
}

/* Key schedule: derive (ROUNDS+1) subkeys by rotating master key */
static void key_schedule(uint64_t master, uint64_t rk[ROUNDS + 1]) {
    for (int i = 0; i <= ROUNDS; i++)
        rk[i] = rotl64(master, i * 8);
}

/* Apply S-Box to all 16 nibbles in the 64-bit block */
static uint64_t sub_nibbles(uint64_t block) {
    uint64_t out = 0;
    for (int i = 0; i < 16; i++) {
        int sh = (15 - i) * 4;
        out |= (uint64_t)SBOX[(block >> sh) & 0xF] << sh;
    }
    return out;
}

/*
 * Bit permutation: bit at position i (0 = MSB) moves to position p(i).
 * With i = nibble*4 + bit_in_nibble → p(i) = bit_in_nibble*16 + nibble.
 * Each output nibble receives one bit from 16 different S-Boxes.
 */
static uint64_t permute(uint64_t block) {
    uint64_t out = 0;
    for (int i = 0; i < 64; i++) {
        int dst = (i % 4) * 16 + (i / 4);
        out |= ((block >> (63 - i)) & 1ULL) << (63 - dst);
    }
    return out;
}

/* SPN-64 encrypt: initial key mix + 4 rounds of Sub → Permute → XOR */
uint64_t spn64_encrypt(uint64_t pt, uint64_t master_key) {
    uint64_t rk[ROUNDS + 1];
    key_schedule(master_key, rk);

    uint64_t state = pt ^ rk[0];

    for (int r = 1; r <= ROUNDS; r++) {
        state = sub_nibbles(state);
        if (r < ROUNDS)
            state = permute(state);
        state ^= rk[r];
    }
    return state;
}

int main(int argc, char *argv[]) {
    uint64_t key, pt;

    if (argc == 3) {
        char *end;
        key = strtoull(argv[1], &end, 16);
        if (*end != '\0' || strlen(argv[1]) > 16) {
            fprintf(stderr, "Error: key must be a hex value up to 16 digits\n");
            return 1;
        }
        pt = strtoull(argv[2], &end, 16);
        if (*end != '\0' || strlen(argv[2]) > 16) {
            fprintf(stderr, "Error: plaintext must be a hex value up to 16 digits\n");
            return 1;
        }
    } else if (argc == 1) {
        key = 0x133457799BBCDFF1ULL;
        pt  = 0x0123456789ABCDEFULL;
    } else {
        fprintf(stderr, "Usage: %s [KEY_HEX PLAINTEXT_HEX]\n", argv[0]);
        fprintf(stderr, "  e.g. %s 133457799BBCDFF1 0123456789ABCDEF\n", argv[0]);
        return 1;
    }

    uint64_t ct = spn64_encrypt(pt, key);

    printf("Key:        %016llX\n", (unsigned long long)key);
    printf("Plaintext:  %016llX\n", (unsigned long long)pt);
    printf("Ciphertext: %016llX\n", (unsigned long long)ct);
    return 0;
}
