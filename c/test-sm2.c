#include <stdio.h>
#include "./sm2.h"
void bio_to_string(BIO *bio, char **str);
void bio_to_string_with_maxlen(BIO *bio, int max_len, char **str);

int main() {
    char *priKey, *pubKey;
    BIO *bio, *bio_pubKey;

    // Test Generate SM2 Key Pair
    GenEcPairKey(&priKey, &pubKey);
    printf("pubKey: \n %s \n\npriKey: \n %s \n\n", pubKey, priKey);

    // Test PriKey2PubKey
    char *pubKey_form_priKey;
    PriKey2PubKey(priKey, &pubKey_form_priKey);
    printf("Get pubKey from priKey: \n %s \n", pubKey_form_priKey);

    // Test CreateEVP_PKEY
    EVP_PKEY *evp_pkey, *test_evp_pkey;
    BUF_MEM *bmBuf;
    CreateEVP_PKEY((unsigned char *)pubKey, 1, &evp_pkey);

    // Get ec_key from evp_pkey
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(evp_pkey);

    // Get pubkey from ec_key
    bio = BIO_new(BIO_s_mem());
    i2d_EC_PUBKEY_bio(bio, ec_key);

    // Recive pubKey from BIO
    bio_pubKey = BIO_new(BIO_s_mem());
    test_evp_pkey = d2i_PUBKEY_bio(bio, NULL);
    PEM_write_bio_PUBKEY(bio_pubKey, test_evp_pkey);
    char *test_pub_str;
    bio_to_string(bio_pubKey, &test_pub_str);
    printf("Get pubKey from BIO: \n %s \n", test_pub_str);

    // test Encrypt & Decrypt
    char test_plainText[22] = "aaabbbcccdddeeefffggg";
    char *test_encryptedText, *test_decryptedText;
    int test_encryptedText_len, test_decryptedText_len;
    Encrypt(test_plainText, strlen(test_plainText), &test_encryptedText, &test_encryptedText_len, pubKey);
    printf("Encrypted Data: \n %s \n", test_encryptedText);
    Decrypt(test_encryptedText, test_encryptedText_len, &test_decryptedText, &test_decryptedText_len, priKey);
    printf("Decrypted Data: \n %s \n", test_decryptedText);

    // test Sign & Verify
    char *test_sig;
    int test_sig_len;
    Sign(test_plainText, strlen(test_plainText), &test_sig, &test_sig_len, priKey);
    printf("Signed Text: \n %s \n", test_sig);
    int verifyResult = Verify(test_plainText, strlen(test_plainText), test_sig, test_sig_len, pubKey);
    printf("Verify Result: \n %d \n", verifyResult);
    return 0;
}

void bio_to_string_with_maxlen(BIO *bio, int max_len, char **str) {
    char buffer[max_len];
    memset(buffer, 0, max_len);
    BIO_read(bio, buffer, max_len - 1);
    *str = buffer;
}

void bio_to_string(BIO *bio, char **str) {
    char *temp;
    int readSize = (int)BIO_get_mem_data(bio, &temp);
    *str = (char *)malloc(readSize);
    BIO_read(bio, *str, readSize);
}