//  The TOR netowrk salted URL address search program.
// See toronion-peper.c for the 1st version of this idea.
// Notes:
// How do I use gcc with this source,
// gcc -0 toronion-salt toronion-salt.c -lm -lssl -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define RSA_KEY_BITS 1024
#define ONION_LEN 16
#define ONION_PREFIX "406"
#define MAX_ITERATIONS 120000

void base32_encode(const unsigned char *input, int lenght, char *output) {
static const char base32_chars[] = "abcdefghijklmnopqrstuvwxyz234567";
int i, index, digit;
int curr_byte, next_byte;
for (i=0, index=0; i < lenght;) {
curr_byte = input[i] >= 0 ? input[i]:input[i]+256;
if (i+1<lenght) {
next_byte = input[i+1] >=0 ? input[i+1]:input[i+1]+256;
} else {
next_byte=0;
}
digit=curr_byte >> 3;
output[index++]=base32_chars[digit];
digit=(curr_byte & 7) << 2 | next_byte >> 6;
output[index++]=base32_chars[digit];
i++;
if (index >= ONION_LEN) break;
 }
}

void clear_screen() { printf("\033[H\033[J"); system("clear"); }

int main() {
RSA *rsa = NULL;
BIGNUM *bn = NULL;
unsigned char*public_key_der = NULL;
int public_key_len;
unsigned char hash[SHA_DIGEST_LENGTH];
char onion_address[ONION_LEN+1];
unsigned char seed[32];
if (!RAND_bytes(seed, sizeof(seed))) {
fprintf(stderr, "Error: failed to generate random seed\n");
return 1;
}
RAND_seed(seed, sizeof(seed));
bn=BN_new();
if (!BN_set_word(bn, RSA_F4)) {
fprintf(stderr,"Error: Failed to set exponent\n");
BN_free(bn);
return 1;
}
int iteration=0;
time_t start_time, current_time;
double elapsed_time, estimated_total_time, remaining_time;
start_time= time(NULL);

do {
rsa=RSA_new();
if(!RSA_generate_key_ex(rsa, RSA_KEY_BITS, bn, NULL)) {
fprintf(stderr,"Error:Failed to generate RSA key\n");
RSA_free(rsa);
BN_free(bn);
return 1;
}
public_key_der=NULL;
public_key_len=i2d_RSAPublicKey(rsa, &public_key_der);
if (public_key_len < 0 || public_key_der == NULL) { 
fprintf(stderr,"Error: Failed to convert RSA key to DER format\n");
RSA_free(rsa);
BN_free(bn);
if (public_key_der) { OPENSSL_free(public_key_der); }
return 1;
}
SHA1(public_key_der, public_key_len, hash);
base32_encode(hash, 10, onion_address);
OPENSSL_free(public_key_der);
RSA_free(rsa);
iteration++;
current_time=time(NULL);
elapsed_time=difftime(current_time, start_time);
if (iteration > 0) {
estimated_total_time=(elapsed_time / iteration) * MAX_ITERATIONS;
remaining_time=estimated_total_time-elapsed_time;
} else {
remaining_time=0;
}
clear_screen();
printf("\r  [ Estimated time to Completion: %.2f seconds | Iteration: %d/%d | Remaining: %d ] ", remaining_time, iteration, MAX_ITERATIONS, MAX_ITERATIONS-iteration);
fflush(stdout);
} while (strncmp(onion_address, ONION_PREFIX, strlen(ONION_PREFIX)) !=0 && iteration < MAX_ITERATIONS);
printf("\n");
if (iteration >= MAX_ITERATIONS) {
printf("\nFailed to find a matching address within %d iterations.\n", MAX_ITERATIONS);
} else {
printf("\nFound matching address:\n %s.onion\n", onion_address);
}
BN_free(bn);
return 0;
}
