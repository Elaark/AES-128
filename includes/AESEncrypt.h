#ifndef AESENCRYPT_H
#define AESENCRYPT_H

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int encrypt_file_cbc(const char *in_filename, const char *out_filename, const uint8_t key[16], const uint8_t iv_in[16]);

#endif