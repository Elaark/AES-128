#include <stdio.h>
#include <stdint.h>

int generate_random_key(uint8_t key[16]) {
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom == NULL) {
        perror("Error opening /dev/urandom");
        return 0;
    }
    
    size_t read_bytes = fread(key, 1, 16, urandom);
    fclose(urandom);
    
    if (read_bytes != 16) {
        return 0;
    }
    return 1;
}

int main(void) {
    uint8_t key[16];
    
    if (!generate_random_key(key)) {
        fprintf(stderr, "Error : can't generate key.\n");
        return 1;
    }
    
    for (int i = 0; i < 16; i++) {
        printf("%02x", key[i]);
    }
    
    printf("\n");
    
    return 0;
}