#ifndef AESFUNCTIONS_H
#define AESFUNCTIONS_H

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

void print_key(const uint8_t *key);
void print_round_keys(const uint8_t *round_keys);
void print_hex(const char *label, const uint8_t *data);
void print_state_ascii(const uint8_t *state);

void KeyExpansion(const uint8_t k[16], uint8_t *round_keys);
void RotWord(uint8_t word[4]);
void Subword(uint8_t word[4]);
void AddRoundKey(uint8_t state[16], const uint8_t *round_key);
void SubBytes(uint8_t state[16]);
void ShiftRows(uint8_t state[16]);
void MixColumns(uint8_t state[16]);
void InvMixColumns(uint8_t state[16]);
void InvShiftRows(uint8_t state[16]);
void InvSubBytes(uint8_t state[16]);

void xor_block(uint8_t *state, const uint8_t *iv);
ssize_t read_block(int fd, uint8_t block[16]);

#endif