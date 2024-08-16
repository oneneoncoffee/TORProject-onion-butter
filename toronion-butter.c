// Project Onion Butter - A fast as hell way to make onion urls on a cromebook.
// Notes:
// How do I make this sourc code with gcc,
// gcc -o toronion-butter toronion-butter.c -lssl -lm -lcrypto
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <math.h>


void base32_encode(const unsigned char *in, int in_len, char *out) {
static const char *base32_chars = "abcdefghijklmnopqrstuvwxyz234567";
int i, index = 0, bits = 0;
unsigned int buffer = 0;
for (i = 0; i < in_len; i++) {
	buffer = (buffer << 8) | in[i];
	bits += 8;
while (bits >= 5) {
	out[index++] = base32_chars[(buffer >> (bits - 5)) & 0x1F];
	bits -= 8;
       }
   }
  if (bits > 0) {
	out[index++] = base32_chars[(buffer << (5 - bits)) &  0x1F];
}
out[index] = '\0';
}

// 1st version deaft of this base32_encode was fast but buggy weird.
//
//void base32_encode(const unsigned char *in, int in_len, char *out) {
//static const char *base32_chars = "abcdefghijklmnopqrstuvwxyz234567";
//int i, index, digit;
//int currByte, nextByte;
//memset(out, 0, 57);
//for (i = 0, index = 0, digit = 0; i < in_len;) {
//	currByte = in[i];
//	if (digit > 3) {
//	    if ((i + 1) < in_len) {
//			nextByte = in[i + 1];
//	} else {
//		nextByte = 0;
//	}
//	currByte =  currByte & (0xff >> digit);
//	currByte <<= (8 - digit);
//	currByte |= (nextByte >> (digit +3));
//	i++;
//	digit = (digit + 5) % 8;
//	} else {
//        currByte = (currByte >> (3 - digit)) & 0x1f;
//	digit = (digit + 5) % 8;
//	if (digit == 0) i++;
//}
//out[index++] = base32_chars[currByte];
//}
//out[index] = '\0';
//}

void generate_onion_url(FILE *file) {
	int key_length = 2048;
	RSA *rsa = RSA_new();
	BIGNUM *bn = BN_new();
if (!BN_set_word(bn, RSA_F4)) {
fprintf(stderr, "Error setting exponent\n");
return;
}
if (!RSA_generate_key_ex(rsa, key_length, bn, NULL)) {
fprintf(stderr, "Error generating RSA key\n");
return;
}
const BIGNUM *n = RSA_get0_n(rsa);
unsigned char *public_key_bin = malloc(BN_num_bytes(n));
if (public_key_bin == NULL) {
fprintf(stderr, "Error: Memory allocation failed!\n");
return;
}
int pub_len = BN_bn2bin(n, public_key_bin);
unsigned char hash[SHA256_DIGEST_LENGTH];
SHA256(public_key_bin, pub_len, hash);
char onion_address[57];
memset(onion_address, 0, sizeof(onion_address));
base32_encode(hash, 32,onion_address);
printf("\033[31m Public Key:\033[0m");
for (int j = 0; j < pub_len; j++) {
printf("%02x", public_key_bin[j]);
}
printf("\n\n");
printf("\033[31m SHA256 HASH:\033[0m");
for (int j = 0; j < SHA256_DIGEST_LENGTH; j++) {
printf("%02x", hash[j]);
}
printf("\n\n");
printf("\n%s.onion\n\n", onion_address);
fprintf(file,"%s.onion\n", onion_address);
free(public_key_bin);
RSA_free(rsa);
BN_free(bn);
}

int main() {
time_t now = time(NULL);
char filename[64];
snprintf(filename, sizeof(filename), "onion_garden_%ld.log", now);
FILE *file = fopen(filename, "w");
if (file == NULL) {
	fprintf(stderr, "Error: I/O fail opening file for writeing\n");
	return 1;
}
int batch_size = 21;
for (int i = 0; i < batch_size; i++) {
generate_onion_url(file);
}
fclose(file);
printf("\033[32m Onion URLs saved to \033[0m[\033[33m%s\033[0m]\n", filename);
return 0;
}

