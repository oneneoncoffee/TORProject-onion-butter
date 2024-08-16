// Notes:
//How do I make this source with gcc,
//gcc -o toronion-salt  toronion-salt.c -lm -lssl -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <string.h>

#define RSA_KEY_BITS 1024   // Standard encryption of onion address is 1024.
#define ONION_LEN 16
#define ONION_PREFIX "peper"
#define MAX_ITERATIONS 100000

void base32_encode(const unsigned char *input, int length, char *output) {
static const char base32_chars[] = "abcdefghijklmnopqrstuvwxyz234567";
int i;
int index;
int digit;
int curr_byte;
int next_byte;
     for (i = 0, index = 0; i < length;) {
         curr_byte = input[i] >=0 ? input[i] : input[i] + 256;
     if (i + 1 < length) {
         next_byte = input[i + 1] >= 0 ? input[i + 1] : input[i + 1] + 256;
} else {
        next_byte = 0;
}
        digit = (curr_byte & 7) << 2 | next_byte >> 6;
        output[index++] = base32_chars[digit];
i++;
if (index >= ONION_LEN) break;
}
}

void print_progress_bar(int iteration, int total) {
float progress = (float)iteration / total;
int bar_width = 50;
int pos = bar_width * progress;
printf("\rProgress: [");
for (int i = 0; i < bar_width; ++i)  {
if (i<pos) {
printf("=");
} else if (i==pos) { printf(">"); }
else {
printf(" ");
}
}
printf("] %d%%", (int)(progress * 100));
int remaining = total - iteration;

printf("\t Iterations: %d | Remaining: %d", iteration, remaining);
fflush(stdout);
}

void clear_screen() {
printf("\033[H\033[J");
system("clear");
}

void display_intro_message() {
printf("This program gemerates a custom .onion network URL.");
printf("The process can take some time depending on the complexity of the prefix and the key size.\n");
printf("Overall the key size can range from 512 to 1024 bytes of hashed text. \n");
printf("Make sure your PC/Computer/cromebook is pluged on to AC outlet this will drain a battery fast.\n");
printf("Please be patient as the program works to find a matching .onion address.\n");
printf("\n\n");
}

int main() {
clear_screen();
display_intro_message();
RSA *rsa = NULL;
BIGNUM *bn = NULL;
unsigned char *public_key_der = NULL;
int public_key_len;
unsigned char hash[SHA_DIGEST_LENGTH];
char onion_address[ONION_LEN + 1];
bn = BN_new();
if (!BN_set_word(bn, RSA_F4)) {
fprintf(stderr, "\nError: Failed to set exponent\n");
BN_free(bn);
return 1;
}
int iteration = 0;
do {
print_progress_bar(iteration, MAX_ITERATIONS);
rsa = RSA_new();
if (!RSA_generate_key_ex(rsa, RSA_KEY_BITS, bn, NULL)) {
fprintf(stderr, "\nFailed to generate RSA key!\n");
RSA_free(rsa);
BN_free(bn);
return 1;
}
public_key_der = NULL;
public_key_len = i2d_RSAPublicKey(rsa, &public_key_der);
if (public_key_len < 0) {
fprintf(stderr, "\nFailed to convert RSA key to DER format!\n");
RSA_free(rsa);
BN_free(bn);
if (public_key_der) { OPENSSL_free(public_key_der); }
return 1;
}

SHA1(public_key_der, public_key_len, hash);
base32_encode(hash, 10, onion_address);
onion_address[ONION_LEN] = '\0';
OPENSSL_free(public_key_der);
RSA_free(rsa);
iteration++;
} while (strncmp(onion_address, ONION_PREFIX, strlen(ONION_PREFIX)) != 0 && iteration < MAX_ITERATIONS);
printf("\n");
if (iteration >= MAX_ITERATIONS) {
printf("\nFailed to find a matching address within %d iterations.\n", MAX_ITERATIONS);
} else {
printf("Found matching address:%s.onion", onion_address);
}
BN_free(bn);
return 0;
}
