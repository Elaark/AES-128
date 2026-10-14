#ifndef AESDECRYPT_H
#define AESDECRYPT_H

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int decrypt_file_cbc(const char *in_filename, const char *out_filename, const uint8_t key[16]);

#endif