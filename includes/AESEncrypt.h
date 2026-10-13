#ifndef AESENCRYPT_H
#define AESENCRYPT_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

void AESEncrypt(uint8_t state[16], const uint8_t k[16]);
void print_hex(const char *label, const uint8_t *data);

#endif