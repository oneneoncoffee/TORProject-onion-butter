// Makes old V2 onion addresses. Why not?
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#define BASE32_ALPHABET "abcdefghicklmnopqrstuvwxyz234567"
#define ABOUT_PROGRAM "Welcome, to the butter tor example, V2 onion addresses are fundamentally insecure.\n Tor V2 addresses base32-encoded hidden srvice:\n"

void base32_encode(const unsigned char *data, int length, char *result) {
int buffer;
int bitsLeft =0;
int count = 0;
for (int i = 0; i < length; i++) {
buffer <<= 8;
buffer |= data[i] & 0xFF;
bitsLeft += 8;

while (bitsLeft >= 5) {
result[count++] = BASE32_ALPHABET[(buffer >> (bitsLeft - 5)) & 0x1F];
bitsLeft -= 5;        }
}

if (bitsLeft > 0) { 
result[count++] = BASE32_ALPHABET[(buffer << (5 - bitsLeft)) & 0x1F]; 
}
result[count] = '\0';
}

RSA* generate_rsa_key(int bits) {
RSA* rsa = RSA_new();
BIGNUM* e = BN_new();
BN_set_word(e, RSA_F4);

if (!RSA_generate_key_ex(rsa, bits, e, NULL)) {
	fprintf(stderr,"Error: generating RSA key\n");
	RSA_free(rsa);
	BN_free(e);
	return NULL;
        }
	BN_free(e);
	return rsa;
}

int extract_public_key(RSA* rsa, unsigned char* out,  size_t* out_len) {
BIO* bio = BIO_new(BIO_s_mem());
if (!PEM_write_bio_RSA_PUBKEY(bio, rsa)) {
        fprintf(stderr, "Error: writing public key to BIO\n");
	BIO_free(bio);
	return -1;
}
*out_len = BIO_read(bio, out, *out_len);
BIO_free(bio);
return 0;
}

int extract_public_key_der(RSA* rsa, unsigned char** out, size_t* out_len) {
int len = i2d_RSAPublicKey(rsa, NULL);
if (len < 0) {
fprintf(stderr, "Error: writeing public key to DER\n");
return -1;
}
*out = (unsigned char*)malloc(len);
if (*out == NULL) {
fprintf(stderr,"Error: Memory allocation failed\n");
return -1;
}
unsigned char* temp = *out;
len = i2d_RSAPublicKey(rsa, &temp);
if (len < 0) {
fprintf(stderr, "Error: writeing public key to DER.\n");
free(*out);
return -1;
}
*out_len = len;
return 0;
}

void generate_onion_url(unsigned char* pub_key, size_t pub_key_len, char* onion_url) {
unsigned char hash[SHA_DIGEST_LENGTH];
SHA1(pub_key, pub_key_len, hash);
//snprintf(onion_url, 17,"TEST HASH:%02x-%02x-%02x-%02x-%02x", hash[0], hash[1], hash[2], hash[3], hash[4]);
char base32[17];
base32_encode(hash, 10, base32);
snprintf(onion_url, 23, "%s.onion", base32);
}

void batch_generate(int count) {
	for (int i=0; i < count; i++) {
	     RSA* rsa = generate_rsa_key(1024);
		if (!rsa) { continue; }

// unsigned char pub_key[512];
unsigned char *pub_key = NULL;
//size_t pub_key_len = sizeof(pub_key);
size_t pub_key_len = 0;
if (extract_public_key_der(rsa, &pub_key, &pub_key_len) != 0) {
//	if (extract_public_key(rsa, pub_key, &pub_key_len) !=0) {
		RSA_free(rsa);
                continue;
}
//if (extract_public_key_der(rsa, pub_key, &pub_key_len) != 0) {
//RSA_free(rsa);
//continue;
//}

char onion_url[23];
generate_onion_url(pub_key, pub_key_len, onion_url);
printf("\n%s", onion_url);
RSA_free(rsa);
free(pub_key);                                     }
}

int main() {
printf(ABOUT_PROGRAM);
int count = 20;
batch_generate(count);
printf("\n");
return 0;
}
