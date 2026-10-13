#include "../includes/main.h"

// int main(int argc, char **argv) {

// 	(void)argc;
//     (void)argv;

// 	__uint8_t plaintext[16] = "ABCDEF0123456789";
// 	__uint8_t ciphertext[16];

// 	// Test key (16 octets) (128 bits)
// 	const __uint8_t k[16] = {
//         0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
//         0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
//     };

// 	// CYPHER
// 	AESEncrypt(plaintext, k);
// }

int main(void) {
    // 1. Vecteurs de test officiels NIST pour AES-128
    const __uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    const __uint8_t plaintext[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };

    const __uint8_t expected_ciphertext[16] = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
    };

    // 2. Préparation de l'état (state)
    // On copie le plaintext dans 'state' car notre fonction AESEncrypt
    // modifie le tableau directement en place (in-place).
    __uint8_t state[16];
    for (int i = 0; i < 16; i++) {
        state[i] = plaintext[i];
    }

    print_hex("Clé", key);
    print_hex("Plaintext initial", plaintext);
    printf("------------------------------------------------------------\n");

    // 3. Exécution du chiffrement
    AESEncrypt(state, key);

    // 4. Affichage et Comparaison
    printf("------------------------------------------------------------\n");
    print_hex("Ciphertext obtenu", state);
    print_hex("Ciphertext attendu", expected_ciphertext);

    int success = 1;
    for (int i = 0; i < 16; i++) {
        if (state[i] != expected_ciphertext[i]) {
            success = 0;
            break;
        }
    }

    if (success) {
        printf("\n✅ SUCCÈS : L'implémentation AES-128 est conforme au standard NIST !\n");
    } else {
        printf("\n❌ ÉCHEC : Le résultat diffère. Il y a une erreur dans l'une des opérations.\n");
    }

    return 0;
}