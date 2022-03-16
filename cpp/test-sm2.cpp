#include <iostream>
#include <string>
#include <cstring>
#include <memory>
#include <openssl/bio.h>
#include "sm2.h"

using namespace std;
void bio_to_string(BIO *bio, string &data);
void string_to_bio(BIO *bio, string data);

int main() {
    SM2 sm2Handler;
    BIO *bio, *bio_pubKey;
    string priKey, pubKey;

    // Test Generate SM2 Key Pair
    sm2Handler.GenEcPairKey(priKey, pubKey);
    cout << "pubKey: \n" << pubKey << endl;
    cout << "priKey: \n" << priKey << endl;

    // Test PriKey2PubKey
    string pubKey_from_priKey;
    sm2Handler.PriKey2PubKey(priKey, pubKey_from_priKey);
    cout << "Get pubKey from priKey: \n" << pubKey_from_priKey << endl;

    // Test CreateEVP_PKEY
    unsigned char *pubKeyArray = (unsigned char *)pubKey.c_str();
    EVP_PKEY *evp_pkey, *test_evp_pkey;
    sm2Handler.CreateEVP_PKEY(pubKeyArray, 1, &evp_pkey);

    // Get ec_key from evp_pkey
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(evp_pkey);
    
    // Get pubkey from ec_key
    bio = BIO_new(BIO_s_mem());
    i2d_EC_PUBKEY_bio(bio, ec_key);

    // Recive pubKey from BIO
    bio_pubKey = BIO_new(BIO_s_mem());
    test_evp_pkey = d2i_PUBKEY_bio(bio, NULL);
    PEM_write_bio_PUBKEY(bio_pubKey, test_evp_pkey);
    string test_pub_str;
    bio_to_string(bio_pubKey, test_pub_str);
    cout << "Get pubKey from BIO: \n" << test_pub_str << endl;


    // test Encrypt & Decrypt
    string test_plainText = "aaabbbcccdddeeefffggg";
    string test_encryptedText, test_decryptedText;
    int test_encryptedText_len, test_decryptedText_len;
    sm2Handler.Encrypt(test_plainText, test_plainText.length(), test_encryptedText, test_encryptedText_len, pubKey);
    cout << "Encrypted Text: \n" << test_encryptedText << endl;
    sm2Handler.Decrypt(test_encryptedText, test_encryptedText.length(), test_decryptedText, test_decryptedText_len, priKey);
    cout << "Decrypted Text: \n" << test_decryptedText << endl;

    // test Sign & Verify
    string test_sig;
    int test_sig_len;
    sm2Handler.Sign(test_plainText, test_plainText.length(),test_sig, test_sig_len, priKey);
    cout << "Signed Text: \n" << test_sig << endl;
    int verifyResult = sm2Handler.Verify(test_plainText, test_plainText.length(), test_sig,
        test_sig_len, pubKey, pubKey.length());
    cout << "Verify Result: " << verifyResult << endl;
    return 0;
}

void bio_to_string(BIO *bio, string &data) {
    char *temp;
    int readSize = (int)BIO_get_mem_data(bio, &temp);
    data = string(temp, readSize);
}

void string_to_bio(BIO *bio, string data) {
    int dlen = data.length();
    unsigned char *dataArray = (unsigned char *)data.c_str();
    BIO_write(bio, dataArray, dlen);
    return;
}