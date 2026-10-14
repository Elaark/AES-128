#include "../includes/AESEncrypt.h"
#include "../includes/AESFunctions.h"

void AESCipher(uint8_t state[16], const uint8_t k[16]) {

	uint8_t word[176];

	//print_key(k);

	KeyExpansion(k, word);

	//print_round_keys(word);

	AddRoundKey(state, &word[0]);

	for (int i = 1; i <= 9; i++) {
		SubBytes(state);
	 	ShiftRows(state);
	 	MixColumns(state);
	 	AddRoundKey(state, &word[i * 16]);
	}

	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, &word[10 * 16]);
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

    uint8_t current_iv[16];
    for (int i = 0; i < 16; i++) {
        current_iv[i] = iv_in[i];
    }

	write(out_fd, current_iv, 16);
    
	uint8_t buffer[16];
    ssize_t bytes_read;

    while ((bytes_read = read(in_fd, buffer, 16)) == 16) {
        xor_block(buffer, current_iv);
        AESCipher(buffer, key);
        
		write(out_fd, buffer, 16);        
        
		for (int i = 0; i < 16; i++) {
            current_iv[i] = buffer[i];
        }
    }

	if (bytes_read < 0) {
        perror("Error reading input file");
        close(in_fd);
        close(out_fd);
        return 0;
    }

    uint8_t pad_val = 16 - bytes_read;
    for (ssize_t i = bytes_read; i < 16; i++) {
        buffer[i] = pad_val;
    }

    xor_block(buffer, current_iv);
    AESCipher(buffer, key);
    write(out_fd, buffer, 16);

    close(in_fd);
    close(out_fd);
    
    return 1;
    
    return 1;
}