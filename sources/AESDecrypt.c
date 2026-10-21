#include "../includes/AESDecrypt.h"
#include "../includes/AESFunctions.h"

static void AESDecrypt(uint8_t state[16], const uint8_t *round_keys) {

	AddRoundKey(state, &round_keys[10 * 16]);

	for (int i = 9; i >= 1; i--) {
		InvShiftRows(state);
        InvSubBytes(state);
	 	AddRoundKey(state, &round_keys[i * 16]);
        InvMixColumns(state);
	}

	InvShiftRows(state);
	InvSubBytes(state);
    AddRoundKey(state, &round_keys[0]);
}

static int decrypt_fail(int in_fd, int out_fd, const char *out_filename, const char *msg, int use_errno) {
    if (use_errno)
        perror(msg);
    else
        printf("%s\n", msg);
    close(in_fd);
    close(out_fd);
    unlink(out_filename);
    return 0;
}

int decrypt_file_cbc(const char *in_filename, const char *out_filename, const uint8_t key[16]) {

    int in_fd = open(in_filename, O_RDONLY);
    if (in_fd < 0) {
        perror("Error opening encrypted file");
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
    ssize_t bytes_read = read_block(in_fd, current_iv);

    if (bytes_read < 0)
        return decrypt_fail(in_fd, out_fd, out_filename, "Error reading encrypted file", 1);
    if (bytes_read != 16)
        return decrypt_fail(in_fd, out_fd, out_filename, "Error : File is too small or missing IV.", 0);

    uint8_t current_cipher[16];
    uint8_t next_cipher[16];
    uint8_t decrypted[16];

    bytes_read = read_block(in_fd, current_cipher);
    if (bytes_read < 0)
        return decrypt_fail(in_fd, out_fd, out_filename, "Error reading encrypted file", 1);
    if (bytes_read == 0)
        return decrypt_fail(in_fd, out_fd, out_filename, "Error : File contains no encrypted data.", 0);
    if (bytes_read != 16)
        return decrypt_fail(in_fd, out_fd, out_filename, "Error : Encrypted data size is not a multiple of 16.", 0);

    while ((bytes_read = read_block(in_fd, next_cipher)) == 16) {

        for (int i = 0; i < 16; i++)
			decrypted[i] = current_cipher[i];

        AESDecrypt(decrypted, round_keys);

        xor_block(decrypted, current_iv);

        if (write(out_fd, decrypted, 16) != 16)
            return decrypt_fail(in_fd, out_fd, out_filename, "Error writing output file", 1);

        for (int i = 0; i < 16; i++)
			current_iv[i] = current_cipher[i];

        for (int i = 0; i < 16; i++)
			current_cipher[i] = next_cipher[i];
    }

    if (bytes_read < 0)
        return decrypt_fail(in_fd, out_fd, out_filename, "Error reading encrypted file", 1);
    if (bytes_read != 0)
        return decrypt_fail(in_fd, out_fd, out_filename, "Error : Encrypted data size is not a multiple of 16.", 0);

    for (int i = 0; i < 16; i++)
		decrypted[i] = current_cipher[i];

    AESDecrypt(decrypted, round_keys);
    xor_block(decrypted, current_iv);

    uint8_t pad_val = decrypted[15];
    int bad_padding = (pad_val == 0 || pad_val > 16);

    for (int i = 16 - pad_val; !bad_padding && i < 16; i++) {
        if (decrypted[i] != pad_val)
            bad_padding = 1;
    }

    if (bad_padding)
        return decrypt_fail(in_fd, out_fd, out_filename, "Error : Invalid padding. Wrong key or corrupted file.", 0);

    if (write(out_fd, decrypted, 16 - pad_val) != 16 - pad_val)
        return decrypt_fail(in_fd, out_fd, out_filename, "Error writing output file", 1);

    close(in_fd);
    close(out_fd);

    return 1;
}
