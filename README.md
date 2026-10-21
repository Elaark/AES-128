# AES

A from-scratch C implementation of **AES-128** (FIPS-197) in **CBC** mode with **PKCS#7** padding, for encrypting and decrypting files.

> **Warning:** this is an **educational** project. It has not been audited and must not be used to protect real data. See [Limitations and security](#limitations-and-security).

## Build

```sh
make        # builds ./AES and ./keygen
make clean  # removes build/
make fclean # removes build/, AES and keygen
make re     # rebuilds everything
```

## Usage

### Generate a key

```sh
./keygen
# 2252f37b8170959a76309a216fe332e1
```

The key is 128 bits (16 bytes read from `/dev/urandom`), printed as 32 hexadecimal characters.

### Encrypt

```sh
./AES -e file <hex_key>
# -> file.enc
```

### Decrypt

```sh
./AES -d file.enc <hex_key>
# -> file.enc.dec
```

The program returns `0` on success and `1` on error (invalid key, missing file, bad padding, truncated file...). On error, the incomplete output file is deleted.

## Encrypted file format

```
+-------------+-------------------------------------------+
| IV (16 B)   | AES-128-CBC ciphertext + PKCS#7 padding   |
+-------------+-------------------------------------------+
```

A random IV is drawn from `/dev/urandom` for each encryption. The format is compatible with OpenSSL:

```sh
IV=$(head -c 16 file.enc | od -An -tx1 | tr -d ' \n')
tail -c +17 file.enc | openssl enc -d -aes-128-cbc -K <hex_key> -iv "$IV"
```

## Layout

```
includes/           headers
sources/
  main.c            argument parsing, key parsing, IV generation
  AESEncrypt.c      single-block encryption + CBC mode on files
  AESDecrypt.c      single-block decryption + CBC mode on files
  AESFunctions.c    AES primitives (KeyExpansion, SubBytes, ShiftRows, MixColumns, inverses...)
keygen.c            key generator
```

## Limitations and security

The cipher itself is correct: its output is byte-for-byte identical to `openssl enc -aes-128-cbc`. The **tool**, however, has several known weaknesses:

### No authentication (no MAC)

CBC provides confidentiality, **not integrity**.

- **Malleability**: an attacker can modify the ciphertext without knowing the key. For example, flipping a bit in the IV flips the same bit in the first decrypted block. Nothing detects the change.
- **Padding oracle**: the "Invalid padding" message is distinguishable from other errors. If an attacker can submit ciphertexts and observe the result (tool exposed through a service, a script...), they can fully decrypt a file without the key (Vaudenay's attack).

A proper solution would use an authenticated mode (AES-GCM, ChaCha20-Poly1305) or an *encrypt-then-MAC* scheme (HMAC-SHA256 over IV + ciphertext).

### Key passed on the command line

The key is passed as an argument, so it is visible to other users on the machine (`ps`, `/proc/<pid>/cmdline`) and saved in the shell history. Likewise, `keygen` prints the key to standard output.

### Raw key, no password

There is no key derivation (PBKDF2, scrypt, Argon2): you have to manage and store the 128-bit hex key yourself. If it is lost, the data cannot be recovered.

### Side channels

- The S-box is implemented with **in-memory lookup tables**, whose accesses depend on the key and the data. The implementation is therefore vulnerable to cache-timing attacks.
- The padding check is not constant-time.
- `xtime` / `gf_mul` contain data-dependent branches.

### Sensitive data in memory

The key and the round keys (`round_keys`) are not wiped from memory after use. They can end up in a core dump or in swap.

### File handling

- The output file (`.enc` / `.dec`) is **overwritten without warning** if it already exists.
- During decryption, plaintext is written to disk before the last block (padding) is checked. On failure the file is deleted, but its contents may remain physically on the disk.
- The output file name is limited to 255 characters. Longer names are truncated.

### Scope

- AES-128 only (no AES-192 or AES-256), CBC mode only.
- No hardware acceleration (AES-NI): much slower than OpenSSL.

**For real use**, prefer well-tested tools: [age](https://github.com/FiloSottile/age), `gpg`, or a library such as libsodium / OpenSSL (EVP, AES-GCM).
