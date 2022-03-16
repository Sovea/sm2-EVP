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
#include <string>
using namespace std;
class SM2 {
private:
public:
    SM2() {}

    //
    // @brief: Get EVP_PKEY by pubKey or priKey
    // @param: key -> the pubKey or priKey
    // @param: is_public -> if the key is pubKey
    // @param: out_ecKey -> target EVP_PKEY
    // @ret: whether succeed
    //
    static bool CreateEVP_PKEY(unsigned char *key, int is_public, EVP_PKEY **out_ecKey);

    //
    // @brief: Get pubKey by priKey
    // @param: in_priKey -> the priKey
    // @param: out_pubKey -> target pubKey
    // @ret: whether succeed
    //
    static bool PriKey2PubKey(string in_priKey, string &out_pubKey);

    //
    // @brief: Generate SM2 Key Pair (pem)
    // @param: out_priKey -> target priKey
    // @param: out_pubKey -> target pubKey
    // @ret: result code
    //
    static int GenEcPairKey(string &out_priKey, string &out_pubKey);

    //
    // @brief: Sign data with SM2 priKey
    // @param: in_buf -> the data to be signed
    // @param: in_buflen -> length of the target data
    // @param: out_sig -> signed data
    // @param: len_sig -> length of the signed data
    // @param: priKey
    // @ret: result code
    //
    static int Sign(string in_buf, int in_buflen, string &out_sig, int &len_sig, string priKey);

    //
    // @brief: Verify signed data with SM2 pubkey
    // @param: in_buf -> the data to be verified
    // @param: in_buflen -> length of the target data
    // @param: sig -> signed data
    // @param: siglen -> length of the signed data
    // @param: pubkey
    // @param: keylen -> length of the pubkey
    // @ret: result code
    //
    static int Verify(string in_buf, const int buflen, string sig, const int siglen, string pubkey, const int keylen);

    //
    // @brief: Encrypt data with SM2 pubkey
    // @param: in_buf -> the data to be encrypted
    // @param: in_buflen -> length of the target data
    // @param: out_encrypted -> save encrypted data
    // @param: len_encrypted -> save length of the encrypted data
    // @param: pubkey
    // @ret: result code
    //
    static int Encrypt(string in_buf, int in_buflen, string &out_encrypted, int &len_encrypted, string pubKey);

    //
    // @brief: Decrypt data with SM2 prikey
    // @param: in_buf -> the encrypted data
    // @param: in_buflen -> length of the target encrypted data
    // @param: out_plaint -> save decrypted data
    // @param: len_plaint -> save length of the decrypted data
    // @param: prikey
    // @ret: result code
    //
    static int Decrypt(string in_buf, int in_buflen, string &out_plaint, int &len_plaint, string prikey);
};
