#include "../includes/AESDecrypt.h"
#include "../includes/AESFunctions.h"

void AESDecrypt(uint8_t state[16], const uint8_t k[16]) {

	uint8_t word[176];

	//print_key(k);

	KeyExpansion(k, word);

	//print_round_keys(word);

	AddRoundKey(state, &word[10 * 16]);

	for (int i = 9; i >= 1; i--) {
		InvShiftRows(state);
        InvSubBytes(state);
	 	AddRoundKey(state, &word[i * 16]);
        InvMixColumns(state);
	}

	InvShiftRows(state);
	InvSubBytes(state);
    AddRoundKey(state, &word[0]);
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

    uint8_t current_iv[16];
    
    if (read(in_fd, current_iv, 16) != 16) {
        printf("Error : File is too small or missing IV.\n");
        close(in_fd); close(out_fd);
        return 0;
    }

    uint8_t current_cipher[16];
    uint8_t next_cipher[16];
    uint8_t decrypted[16];
    ssize_t bytes_read;

    if (read(in_fd, current_cipher, 16) != 16) {
        printf("Error : File contains no encrypted data.\n");
        close(in_fd); 
		close(out_fd);
        
		return 0;
    }

    while ((bytes_read = read(in_fd, next_cipher, 16)) == 16) {
        
        for (int i = 0; i < 16; i++) 
			decrypted[i] = current_cipher[i];
        
        AESDecrypt(decrypted, key);
        
        xor_block(decrypted, current_iv);
        
        write(out_fd, decrypted, 16);
        
        for (int i = 0; i < 16; i++) 
			current_iv[i] = current_cipher[i];
        
        for (int i = 0; i < 16; i++) 
			current_cipher[i] = next_cipher[i];
    }

    for (int i = 0; i < 16; i++)
		decrypted[i] = current_cipher[i];
    
    AESDecrypt(decrypted, key);
    xor_block(decrypted, current_iv);

    uint8_t pad_val = decrypted[15];
    
    if (pad_val == 0 || pad_val > 16) {
        printf("Error : Invalid padding. Wrong key or corrupted file.\n");
        close(in_fd); close(out_fd);
        return 0;
    }

    write(out_fd, decrypted, 16 - pad_val);

    close(in_fd);
    close(out_fd);
    
    return 1;
}