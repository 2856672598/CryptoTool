#ifndef CRYPTOUTILS_H
#define CRYPTOUTILS_H

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/sm2.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>
#include <openssl/ec.h>
#include <openssl/param_build.h>


#include <functional>
#include <QString>
#include <QByteArray>
#include <QColor>

#include <memory>

enum HashType {
    HASH_SHA1 = 1,
    HASH_SHA256 = 2,
    HASH_SHA384 = 3,
    HASH_SHA512 = 4,
    HASH_MD5 = 5,
    HASH_SM3 = 6
};

#define SM2_USER_ID "1234567812345678"
#define SM2_USER_ID_LEN strlen(SM2_USER_ID)

using BIGNUM_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using X509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using X509_REQ_ptr = std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)>;
using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using EC_GROUP_ptr = std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)>;
//int sm2_compute_z_digest(uint8_t *out,
//                         const EVP_MD *digest,
//                         const uint8_t *id,
//                         const size_t id_len,
//                         const EC_KEY *key);


class CryptoUtils {
public:
    using LogCallback = std::function<void(const QString&, const QColor& color)>;

    explicit CryptoUtils(LogCallback logCallback);

    EVP_PKEY* LoadSM2PublicKey(const unsigned char *x_bin, int x_len,
                               const unsigned char *y_bin, int y_len);
    EVP_PKEY* LoadRSAPublicKey(const unsigned char *n_data, int n_len,
                               const unsigned char *e_data, int e_len);

    void setCertPaths(const QString& sm2CertPath, const QString& sm2PrivateKeyPath,
                      const QString& rsaCertPath, const QString& rsaPrivateKeyPath);

    int LoadCACertAndPrikey(const char* caCertPath, const char* caPrikeyPath,
                            X509** cert, EVP_PKEY** prikey);

    /* 验证签名，传入的为原文数据 */
    int DigestVerify(EVP_PKEY* pubKey, const EVP_MD* hashAlg, const unsigned char* sig
                     , size_t sigLen, const unsigned char* tbs, size_t tbsLen, const char* userId, size_t idLen);

    /* HASH */
    int Digest(const char *algorithm, const unsigned char *data, size_t data_len,
               unsigned char *out_hash, unsigned int *out_len);

    int VerifyRecover(EVP_PKEY* key, const unsigned char *ciphertext, size_t ciphertext_len,
                      unsigned char* decryptData, size_t *decrypted_len);
    int sm2_sig_toder(const unsigned char *r, int r_len,
                      const unsigned char *s, int s_len, unsigned char* out, int* outSize);

    int CertReqVerify(const char *p10_data, int p10_len);

    void MakeCert(const char *p10_string, char** ppcertData, bool isVerifyCsr);
    int x509CertificateToPEM(X509 *cert, char* outData, int* outDataSize);
    void ParsePubkey(EVP_PKEY *pkey);
    void ParseP10(const unsigned char *p10_data, int p10_len);
    unsigned char *remove_pkcs1_padding(const unsigned char *data, size_t data_len, size_t *out_len);

    /* SM2 验签，传入的为hash值 */
    bool sm2_verify(EVP_PKEY* pkey, const unsigned char* der_sign, size_t der_sig_len,
                    const unsigned char* dgst, size_t dgst_len);
private:
    void printLog(const QString&);
    void printErr(const QString&);
    QString toHex(const unsigned char* data, int len);
private:
    LogCallback logCallback;
    QString m_sm2CertPath;
    QString m_sm2PrivateKeyPath;
    QString m_rsaCertPath;
    QString m_rsaPrivateKeyPath;
};

#endif // CRYPTOUTILS_H
