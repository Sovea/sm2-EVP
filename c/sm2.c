#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/ossl_typ.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/opensslconf.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <string.h>
#include "sm2.h"

int GenEcPairKey(char **out_priKey, char **out_pubKey)
{
    EC_KEY *ecKey;
    EC_GROUP *ecGroup;
    int ret_val = -1;
    if (NULL == (ecKey = EC_KEY_new())) {
        return -1;
    }

    if (NULL == (ecGroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1))) {
        EC_KEY_free(ecKey);
        return -2;
    }

    if (EC_KEY_set_group(ecKey, ecGroup) != 1) {
        EC_GROUP_free(ecGroup);
        EC_KEY_free(ecKey);
        return -3;
    }

    if (!EC_KEY_generate_key(ecKey)) {
        EC_GROUP_free(ecGroup);
        EC_KEY_free(ecKey);
        return -3;
    }

    size_t pri_len;
    size_t pub_len;
    char *pri_key = NULL;
    char *pub_key = NULL;

    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_ECPrivateKey(pri, ecKey, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_EC_PUBKEY(pub, ecKey);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);
    pri_key = (char *)malloc(pri_len + 1);
    pub_key = (char *)malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    *out_pubKey = (char *)malloc(pub_len + 1);
    *out_priKey = (char *)malloc(pri_len + 1);
    memset(*out_pubKey, 0, pub_len + 1);
    memset(*out_priKey, 0, pri_len + 1);
    memcpy(*out_pubKey, pub_key, pub_len + 1);
    memcpy(*out_priKey, pri_key, pri_len + 1);
    BIO_free_all(pub);
    BIO_free_all(pri);
    free(pri_key);
    free(pub_key);
    EC_GROUP_free(ecGroup);
    EC_KEY_free(ecKey);
    return 0;
}

bool PriKey2PubKey(char *in_priKey, char **out_pubKey) {
    BIO *keybio = NULL;
    keybio = BIO_new_mem_buf(in_priKey, -1);

    if (keybio == NULL) {
        printf("BIO_new_mem_buf failed.\n");
        return false;
    }

    EC_KEY *ecKey = PEM_read_bio_ECPrivateKey(keybio, NULL, NULL, NULL);
    if (ecKey == NULL) {
        printf("PEM_read_bio_ECPrivateKey failed.");
        BIO_free(keybio);
        return false;
    }

    BIO *pub = BIO_new(BIO_s_mem());
    PEM_write_bio_EC_PUBKEY(pub, ecKey);
    int pub_len = BIO_pending(pub);
    char *pub_key = (char *)malloc(pub_len + 1);
    BIO_read(pub, pub_key, pub_len);
    pub_key[pub_len] = '\0';

    *out_pubKey = pub_key;

    BIO_free(pub);
    BIO_free(keybio);
    return true;
}

bool CreateEVP_PKEY(unsigned char *key, int is_public, EVP_PKEY **out_pKey) {
    BIO *keybio = NULL;
    keybio = BIO_new_mem_buf(key, -1);

    if (keybio == NULL) {
        printf("BIO_new_mem_buf failed.\n");
        return false;
    }

    if (is_public) {
        *out_pKey = PEM_read_bio_PUBKEY(keybio, NULL, NULL, NULL);
    } else {
        *out_pKey = PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL);
    }

    if (*out_pKey == NULL) {
        printf("Failed to Get Key");
        BIO_free(keybio);
        return false;
    }

    BIO_free(keybio);
    return true;
}

int Encrypt(char *in_buf, int in_buflen, char **out_encrypted, int *len_encrypted, char *pubKey) {
    int ret = -1, i;
    EVP_PKEY_CTX *ectx = NULL;
    EVP_PKEY *pkey = NULL;
    EC_KEY *key_pair = NULL;
    unsigned char *ciphertext = NULL;
    size_t ciphertext_len, plaintext_len;
    CreateEVP_PKEY((unsigned char *)pubKey, 1, &pkey);
    /* compute SM2 encryption */
    if ((EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2)) != 1) {
        printf("EVP_PKEY_set_alias_type failed.");
        goto clean_up;
    }

    if (!(ectx = EVP_PKEY_CTX_new(pkey, NULL))) {
        printf("EVP_PKEY_CTX_new failed.");
        goto clean_up;
    }

    if ((EVP_PKEY_encrypt_init(ectx)) != 1) {
        printf("EVP_PKEY_encrypt failed.");
        goto clean_up;
    }

    if ((EVP_PKEY_encrypt(ectx, NULL, &ciphertext_len, (const unsigned char *)in_buf, in_buflen)) != 1) {
        printf("EVP_PKEY_set_alias_type failed.");
        goto clean_up;
    }

    if (!(ciphertext = (unsigned char *)malloc(ciphertext_len))) {
        goto clean_up;
    }

    if ((EVP_PKEY_encrypt(ectx, ciphertext, &ciphertext_len, (const unsigned char *)in_buf, in_buflen)) != 1) {
        printf("EVP_PKEY_encrypt failed.");
        goto clean_up;
    }

    *out_encrypted = (char *)malloc(ciphertext_len);
    memset(*out_encrypted, 0, ciphertext_len);
    memcpy(*out_encrypted, ciphertext, ciphertext_len);
    *len_encrypted = ciphertext_len;
    ret = 0;
clean_up:
    if (pkey) {
        EVP_PKEY_free(pkey);
    }

    if (ectx) {
        EVP_PKEY_CTX_free(ectx);
    }

    if (ciphertext) {
        free(ciphertext);
    }

    return ret;
}

int Decrypt(char *in_buf, int in_buflen, char **out_plaint, int *len_plaint, char *prikey) {
    int ret = -1, i;
    EVP_PKEY_CTX *pctx = NULL, *ectx = NULL;
    EVP_PKEY *pkey = NULL;
    EC_KEY *key_pair = NULL;
    unsigned char *plaintext = NULL;
    size_t ciphertext_len, plaintext_len;

    CreateEVP_PKEY((unsigned char *)prikey, 0, &pkey);

    if ((EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2)) != 1) {
        printf("EVP_PKEY_set_alias_type failed.");
        goto clean_up;
    }

    if (!(ectx = EVP_PKEY_CTX_new(pkey, NULL))) {
        printf("EVP_PKEY_CTX_new failed.");
        goto clean_up;
    }

    /* compute SM2 decryption */
    if ((EVP_PKEY_decrypt_init(ectx)) != 1) {
        printf("EVP_PKEY_decrypt_init failed.");
        goto clean_up;
    }

    if ((EVP_PKEY_decrypt(ectx, NULL, &plaintext_len, (const unsigned char *)in_buf, in_buflen)) != 1) {
        printf("EVP_PKEY_decrypt failed.");
        goto clean_up;
    }

    if (!(plaintext = (unsigned char *)malloc(plaintext_len))) {
        goto clean_up;
    }

    if ((EVP_PKEY_decrypt(ectx, plaintext, &plaintext_len, (const unsigned char *)in_buf, in_buflen)) != 1) {
        printf("EVP_PKEY_decrypt failed.");
        goto clean_up;
    }
    *out_plaint = (char *)malloc(plaintext_len);
    memset(*out_plaint, 0, plaintext_len);
    memcpy(*out_plaint, plaintext, plaintext_len);
    *len_plaint = plaintext_len;
    ret = 0;
clean_up:
    if (pctx) {
        EVP_PKEY_CTX_free(pctx);
    }

    if (pkey) {
        EVP_PKEY_free(pkey);
    }

    if (ectx) {
        EVP_PKEY_CTX_free(ectx);
    }

    if (plaintext) {
        free(plaintext);
    }

    return ret;
}