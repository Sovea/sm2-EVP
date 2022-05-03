### sm2-EVP

This project is a simple sm2 tool class(C++)/function(C) written using openssl EVP.

| Capable Function |                Brief                 | CPP  |  C   |
| :--------------: | :----------------------------------: | :--: | :--: |
|   GenEcPairKey   |    *Generate SM2 Key Pair (pem)*     |  ✔️   |  ✔️   |
|  PriKey2PubKey   |        *Get pubKey by priKey*        |  ✔️   |  ✔️   |
|  CreateEVP_PKEY  |  *Get EVP_PKEY by pubKey or priKey*  |  ✔️   |  ✔️   |
|     Encrypt      |    *Encrypt data with SM2 pubkey*    |  ✔️   |  ✔️   |
|     Decrypt      |    *Decrypt data with SM2 prikey*    |  ✔️   |  ✔️   |
|       Sign       |     *Sign data with SM2 priKey*      |  ✔️   |  ✔️   |
|      Verify      | *Verify signed data with SM2 pubkey* |  ✔️   |  ✔️   |
