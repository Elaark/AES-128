#include "../includes/AESEncrypt.h"
#include "../includes/AESFunctions.h"

static void AESCipher(uint8_t state[16], const uint8_t *round_keys) {

	AddRoundKey(state, &round_keys[0]);

	for (int i = 1; i <= 9; i++) {
		SubBytes(state);
	 	ShiftRows(state);
	 	MixColumns(state);
	 	AddRoundKey(state, &round_keys[i * 16]);
	}

	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, &round_keys[10 * 16]);
}

static int encrypt_fail(int in_fd, int out_fd, const char *out_filename, const char *msg) {
    if (msg)
        perror(msg);
    close(in_fd);
    close(out_fd);
    unlink(out_filename);
    return 0;
}

int encrypt_file_cbc(const char *in_filename, const char *out_filename, const uint8_t key[16], const uint8_t iv_in[16]) {

	int in_fd = open(in_filename, O_RDONLY);
    if (in_fd < 0) {
        perror("Error opening input file");
        return 0;
    }

    int out_fd = open(out_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        perror("Error opening output file");
        close(in_fd);
        return 0;
    }

    uint8_t round_keys[176];
    KeyExpansion(key, round_keys);

    uint8_t current_iv[16];
    for (int i = 0; i < 16; i++) {
        current_iv[i] = iv_in[i];
    }

	if (write(out_fd, current_iv, 16) != 16)
        return encrypt_fail(in_fd, out_fd, out_filename, "Error writing output file");

	uint8_t buffer[16];
    ssize_t bytes_read;

    while ((bytes_read = read_block(in_fd, buffer)) == 16) {
        xor_block(buffer, current_iv);
        AESCipher(buffer, round_keys);

		if (write(out_fd, buffer, 16) != 16)
            return encrypt_fail(in_fd, out_fd, out_filename, "Error writing output file");

		for (int i = 0; i < 16; i++) {
            current_iv[i] = buffer[i];
        }
    }

	if (bytes_read < 0)
        return encrypt_fail(in_fd, out_fd, out_filename, "Error reading input file");

    uint8_t pad_val = 16 - bytes_read;
    for (ssize_t i = bytes_read; i < 16; i++) {
        buffer[i] = pad_val;
    }

    xor_block(buffer, current_iv);
    AESCipher(buffer, round_keys);
    if (write(out_fd, buffer, 16) != 16)
        return encrypt_fail(in_fd, out_fd, out_filename, "Error writing output file");

    close(in_fd);
    close(out_fd);

    return 1;
}
