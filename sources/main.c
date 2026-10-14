#include "../includes/main.h"
#include "../includes/AESEncrypt.h"
#include "../includes/AESDecrypt.h"

#include "../includes/main.h"
#include "../includes/AESEncrypt.h"
#include "../includes/AESDecrypt.h"

size_t ft_strlen(char *str) {
    if (!str)
        return (0);
    int i = 0;
    while (str && str[i])
        i++;
    return (i);
}

uint8_t hex_char_to_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

void parse_hex_key(const char *hex_string, uint8_t key[16]) {
    for (int i = 0; i < 16; i++) {
        key[i] = (hex_char_to_val(hex_string[2 * i]) << 4) | 
                  hex_char_to_val(hex_string[2 * i + 1]);
    }
}

int generate_random_iv(uint8_t iv[16]) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("Can't open /dev/urandom");
        return 0;
    }
    
    ssize_t bytes_read = read(fd, iv, 16);
    close(fd);
    
    return (bytes_read == 16);
}

int print_usage(void) {
    printf("Usage : ./AES -option file key_hex\n");
    printf("-e : cipher\n-d : decipher\n");
    printf("key_hex : 32 hexadecimal characters (128 bits key)\n");
    return 1;
}

int main(int argc, char **argv) {
    
    if (argc < 4 || ft_strlen(argv[1]) != 2 || argv[1][0] != '-' || 
        (argv[1][1] != 'e' && argv[1][1] != 'd')) {
        return print_usage();
    }
    
    if (ft_strlen(argv[3]) != 32) {
        printf("Error : Key must be exactly 32 characters long (16 octets).\n");
        return 1;
    }

    uint8_t key[16];
    parse_hex_key(argv[3], key);
    
    char arg = argv[1][1];
    char *filename = argv[2];
    char out_filename[256];
    
    if (arg == 'e') {
        snprintf(out_filename, sizeof(out_filename), "%s.enc", filename);
        
        uint8_t iv[16];
        if (!generate_random_iv(iv)) {
            printf("Error : IV generation failed.\n");
            return 1;
        }

        if (encrypt_file_cbc(filename, out_filename, key, iv)) {
            printf("Cipher done.\n");
        } else {
            printf("Error when ciphering file.\n");
        }
    } else if (arg == 'd') {

        snprintf(out_filename, sizeof(out_filename), "%s.dec", filename);
        
        if (decrypt_file_cbc(filename, out_filename, key)) {
            printf("Decipher done.\n");
        } 
        else {
            printf("Error when deciphering file.\n");
        }
    }

    return 0;
}