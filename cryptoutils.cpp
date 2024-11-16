#include "cryptoutils.h"

#include <cstdio>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/core_names.h>  // For OSSL_PARAM names
#include <openssl/rsa.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/pkcs7.h>
#if 0
int sm2_compute_z_digest(uint8_t *out,
                         const EVP_MD *digest,
                         const uint8_t *id,
                         const size_t id_len,
                         const EC_KEY *key)
{
    int rc = 0;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    BN_CTX *ctx = nullptr;
    EVP_MD_CTX *hash = nullptr;
    BIGNUM *p = nullptr;
    BIGNUM *a = nullptr;
    BIGNUM *b = nullptr;
    BIGNUM *xG = nullptr;
    BIGNUM *yG = nullptr;
    BIGNUM *xA = nullptr;
    BIGNUM *yA = nullptr;
    int p_bytes = 0;
    uint8_t *buf = nullptr;
    uint16_t entl = 0;
    uint8_t e_byte = 0;

    hash = EVP_MD_CTX_new();
    ctx = BN_CTX_new();
    if (hash == nullptr || ctx == nullptr) {
        //SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    xG = BN_CTX_get(ctx);
    yG = BN_CTX_get(ctx);
    xA = BN_CTX_get(ctx);
    yA = BN_CTX_get(ctx);

    if (yA == nullptr) {
        //SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (!EVP_DigestInit(hash, digest)) {
        //SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }

    /* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */

    if (id_len >= (UINT16_MAX / 8)) {
        /* too large */
        //SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, SM2_R_ID_TOO_LARGE);
        goto done;
    }

    entl = (uint16_t)(8 * id_len);

    e_byte = entl >> 8;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        //SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }
    e_byte = entl & 0xFF;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        //SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }

    if (id_len > 0 && !EVP_DigestUpdate(hash, id, id_len)) {
        //SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }

    if (!EC_GROUP_get_curve(group, p, a, b, ctx)) {
        //SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EC_LIB);
        goto done;
    }

    p_bytes = BN_num_bytes(p);
    //buf = OPENSSL_zalloc(p_bytes);
    buf = (uint8_t*)malloc(p_bytes);
    if (buf == nullptr) {
        //SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (BN_bn2binpad(a, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || BN_bn2binpad(b, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || !EC_POINT_get_affine_coordinates(group,
                                                EC_GROUP_get0_generator(group),
                                                xG, yG, ctx)
            || BN_bn2binpad(xG, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || BN_bn2binpad(yG, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || !EC_POINT_get_affine_coordinates(group,
                                                EC_KEY_get0_public_key(key),
                                                xA, yA, ctx)
            || BN_bn2binpad(xA, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || BN_bn2binpad(yA, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || !EVP_DigestFinal(hash, out, nullptr)) {
        //SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    rc = 1;

done:
    OPENSSL_free(buf);
    BN_CTX_free(ctx);
    EVP_MD_CTX_free(hash);
    return rc;
}
#endif

CryptoUtils::CryptoUtils(LogCallback logCallback) 
    : logCallback(logCallback),
      m_sm2CertPath(),
      m_sm2PrivateKeyPath(),
      m_rsaCertPath(),
      m_rsaPrivateKeyPath()
{}


EVP_PKEY* CryptoUtils::LoadSM2PublicKey(const unsigned char *x_bin, int x_len,
                                        const unsigned char *y_bin, int y_len) {

    EVP_PKEY_CTX* pctx = nullptr;
    EC_POINT* point = nullptr;
    OSSL_PARAM params[3];

    EVP_PKEY *pkey = nullptr;
    BIGNUM_ptr x(nullptr, &BN_free);
    BIGNUM_ptr y(nullptr, &BN_free);

    EC_GROUP_ptr group(EC_GROUP_new_by_curve_name(NID_sm2), EC_GROUP_free);
    if (!group.get()) {
        printErr("group == null\n");
    }
    x.reset(BN_bin2bn(x_bin, x_len, nullptr));
    y.reset(BN_bin2bn(y_bin, y_len, nullptr));
    if (!x.get() || !y.get()) {
        printErr("x == null || y == null\n");
        return nullptr;
    }
    pkey = EVP_PKEY_new();
    if (!pkey) {
        printErr("null == pkey\n");
        return nullptr;
    }

    pctx = EVP_PKEY_CTX_new_from_name(nullptr, "SM2", nullptr);
    point = EC_POINT_new(group.get());
    if(nullptr == point) {
        printErr("point == null");
        return nullptr;
    }
    if(1 != EC_POINT_set_affine_coordinates(group.get(), point, x.get(), y.get(), nullptr)) {
        printErr("EC_POINT_set_affine_coordinates err\n");
        return nullptr;
    }
    unsigned char* encoded_pubkey = nullptr;
    size_t encoded_pubkey_len = 0;
    encoded_pubkey_len = EC_POINT_point2buf(group.get(), point, POINT_CONVERSION_UNCOMPRESSED, &encoded_pubkey, nullptr);

    printLog("公钥(DER):");
    printLog(toHex(encoded_pubkey, encoded_pubkey_len));


    // 设置参数
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, encoded_pubkey, encoded_pubkey_len);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "SM2", 0);
    params[2] = OSSL_PARAM_construct_end();

    // 从数据生成公钥
    if (EVP_PKEY_fromdata_init(pctx) <= 0) {
        printErr("Failed to initialize from data context");
        return nullptr;
    }
    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        printErr("Failed to create EVP_PKEY from data");
        return nullptr;
    }
    return pkey;
}

EVP_PKEY* CryptoUtils::LoadRSAPublicKey(const unsigned char *n_data, int n_len, const unsigned char *e_data, int e_len)
{
    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_CTX_ptr pctx(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr), &EVP_PKEY_CTX_free);
    if (!pctx.get()) {
        printErr("Error creating EVP_PKEY_CTX");
        return nullptr;
    }

    if (EVP_PKEY_fromdata_init(pctx.get()) <= 0) {
        printErr("Error initializing key from data context");
        return nullptr;
    }

    BIGNUM_ptr n(BN_bin2bn(n_data, n_len, nullptr), &BN_free);
    BIGNUM_ptr e(BN_bin2bn(e_data, e_len, nullptr), &BN_free);
    if (!n || !e) {
        printErr("Error creating BIGNUMs for RSA key");
        return nullptr;
    }

    OSSL_PARAM_BLD *params_build = OSSL_PARAM_BLD_new();
    if (!params_build) {
        printErr("Error creating OSSL_PARAM_BLD");
        return nullptr;
    }

    if (!OSSL_PARAM_BLD_push_BN(params_build, OSSL_PKEY_PARAM_RSA_N, n.get()) ||
            !OSSL_PARAM_BLD_push_BN(params_build, OSSL_PKEY_PARAM_RSA_E, e.get())) {
        printErr("Error pushing BIGNUMs into param build");
        OSSL_PARAM_BLD_free(params_build);
        return nullptr;
    }

    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(params_build);
    OSSL_PARAM_BLD_free(params_build);
    if (!params) {
        printErr("Error constructing params from build");
        return nullptr;
    }

    if (EVP_PKEY_fromdata(pctx.get(), &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        printErr("Error creating RSA public key from parameters");
        return nullptr;
    }
    return pkey;
}

void CryptoUtils::setCertPaths(const QString& sm2CertPath, const QString& sm2PrivateKeyPath,
                               const QString& rsaCertPath, const QString& rsaPrivateKeyPath)
{
    m_sm2CertPath = sm2CertPath;
    m_sm2PrivateKeyPath = sm2PrivateKeyPath;
    m_rsaCertPath = rsaCertPath;
    m_rsaPrivateKeyPath = rsaPrivateKeyPath;
}

int CryptoUtils::LoadCACertAndPrikey(const char* caCertPath, const char* caPrikeyPath, X509** cert, EVP_PKEY** prikey)
{
    if(nullptr == cert || nullptr == prikey) {
        printErr("加载CA时参数错误");
        return -1;
    }

    // 加载根证 ---->读取CA证书
    BIO_ptr caCertBio(BIO_new_file(caCertPath, "r"), BIO_free);
    if (!caCertBio.get()) {
        printErr("Error reading CA certificate.");
        return -1;
    }

    X509* caCert = PEM_read_bio_X509(caCertBio.get(), nullptr, nullptr, nullptr);
    if (!caCert) {
        printErr("Error loading CA certificate.");
        return -1;
    }

    // 读取CA私钥
    BIO_ptr caKeyBio(BIO_new_file(caPrikeyPath, "r"), BIO_free);
    if (!caKeyBio.get()) {
        printErr("Error reading CA private key.");
        return -1;
    }

    EVP_PKEY *caKey = PEM_read_bio_PrivateKey(caKeyBio.get(), nullptr, nullptr, nullptr);
    if (!caKey) {
        printErr("Error loading CA private key.");
        return -1;
    }
    *cert = caCert;
    *prikey = caKey;
    return 0;
}

int CryptoUtils::DigestVerify(EVP_PKEY* pubKey, const EVP_MD* hashAlg, const unsigned char* sig
                              , size_t sigLen, const unsigned char* tbs, size_t tbsLen, const char* userId, size_t idLen) {

    EVP_MD_CTX_ptr mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!mdctx.get()) {
        printErr("Error creating message digest context.");
        return -1;
    }

    EVP_PKEY_CTX_ptr key_ctx(nullptr, EVP_PKEY_CTX_free);
    if(EVP_PKEY_base_id(pubKey) == EVP_PKEY_SM2 || EVP_PKEY_is_a(pubKey, "SM2")) {
        //创建一个密钥上下文
        key_ctx.reset(EVP_PKEY_CTX_new(pubKey, nullptr));
        if(idLen > 0 && nullptr != userId) {
            //设置用户ID
            int ret = EVP_PKEY_CTX_set1_id(key_ctx.get(), userId, idLen);
            if(1 != ret) {
                //printLog("设置用户ID失败");
                printErr("Error EVP_PKEY_CTX_set1_id.");
                return -1;
            }
            EVP_MD_CTX_set_pkey_ctx(mdctx.get(), key_ctx.get());
        }
    }

    // Initialize the verification operation
    if (EVP_DigestVerifyInit(mdctx.get(), nullptr, hashAlg, nullptr, pubKey) != 1) {
        printErr("Error initializing digest verify.");
        return -1;
    }

    // Add the message data to be verified
    if (EVP_DigestVerifyUpdate(mdctx.get(), tbs, tbsLen) != 1) {
        printErr("Error updating digest verify.");
        return -1;
    }
    return EVP_DigestVerifyFinal(mdctx.get(), sig, sigLen) <=0 ?0:1;
}

int CryptoUtils::Digest(const char *algorithm, const unsigned char *data, size_t data_len, unsigned char *out_hash, unsigned int *out_len)
{
    const EVP_MD *md = EVP_get_digestbyname(algorithm);
    if (nullptr == md) {
        fprintf(stderr, "Unknown message digest %s\n", algorithm);
        return -1;
    }

    EVP_MD_CTX_ptr mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!mdctx.get()) {
        fprintf(stderr, "Error creating context\n");
        return -1;
    }

    if (EVP_DigestInit_ex(mdctx.get(), md, nullptr) != 1) {
        fprintf(stderr, "Error initializing digest\n");
        return -1;
    }

    if (EVP_DigestUpdate(mdctx.get(), data, data_len) != 1) {
        fprintf(stderr, "Error updating digest\n");
        return -1;
    }

    if (EVP_DigestFinal_ex(mdctx.get(), out_hash, out_len) != 1) {
        fprintf(stderr, "Error finalizing digest\n");
        return -1;
    }
    return 0;
}
int CryptoUtils::VerifyRecover(EVP_PKEY* key, const unsigned char *ciphertext, size_t ciphertext_len,
                               unsigned char* decryptData, size_t *decrypted_len) {
    if (nullptr == key || nullptr == decrypted_len || nullptr == decryptData) {
        printErr("Invalid param.");
        return -1;
    }

    // 使用自定义类型管理 EVP_PKEY_CTX 的生命周期
    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new(key, nullptr), EVP_PKEY_CTX_free);
    if (!ctx) {
        printErr("Failed to create context.");
        return -1;
    }

    // 初始化验证和恢复
    if (EVP_PKEY_verify_recover_init(ctx.get()) <= 0) {
        printErr("Failed to initialize verify recover.");
        return -1;
    }

    // 设置填充方式（如果需要）
    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_NO_PADDING) <= 0) {
        printErr("Failed to set padding.");
        return -1;
    }

    if (*decrypted_len < EVP_PKEY_size(key)) {
        return -1;
    }

    // 执行验证和恢复
    if (EVP_PKEY_verify_recover(ctx.get(), decryptData, decrypted_len, ciphertext, ciphertext_len) <= 0) {
        printErr("Error during verify recover.");
        return -1;
    }

    return 0;
}

int CryptoUtils::sm2_sig_toder(const unsigned char *r, int r_len, const unsigned char *s, int s_len
                               , unsigned char* out, int* outSize)
{
    if(nullptr == outSize) {
        return -1;
    }
    ECDSA_SIG* signal = ECDSA_SIG_new();
    BIGNUM_ptr bn_r(BN_bin2bn(r, r_len, nullptr), &BN_free);
    BIGNUM_ptr bn_s(BN_bin2bn(s, s_len, nullptr), &BN_free);

    if(nullptr == bn_r.get() || nullptr == bn_s.get()) {
        return -1;
    }
    if (0 == ECDSA_SIG_set0(signal, bn_r.get(), bn_s.get())) {
        return -1;
    }
    int der_len = i2d_ECDSA_SIG(signal, nullptr);
    unsigned char* p = out;
    if(*outSize >= der_len) {
        if (i2d_ECDSA_SIG(signal, &p) <= 0) {
            return -1;
        }
    }
    *outSize = der_len;
    return 0;
}

int CryptoUtils::CertReqVerify(const char *p10_data, int p10_len)
{
    BIO *bio = BIO_new_mem_buf(p10_data, p10_len);
    if (!bio) {
        printErr("Error creating BIO.\n");
        return -1;
    }

    X509_REQ *req = PEM_read_bio_X509_REQ(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!req) {
        printErr("Error reading the certificate request.\n");
        return -1;
    }
    EVP_PKEY *pkey = X509_REQ_get_pubkey(req);
    if (!pkey) {
        printErr("Error getting public key from request.\n");
        X509_REQ_free(req);
        return -1;
    }

    int isSM2 = EVP_PKEY_is_a(pkey, "SM2");
    if(1 == isSM2) {
        ASN1_OCTET_STRING* sm2UserId = ASN1_OCTET_STRING_new();
        if(nullptr != sm2UserId) {
            ASN1_OCTET_STRING_set(sm2UserId, (const unsigned char*)SM2_USER_ID, SM2_USER_ID_LEN);
        }
        X509_REQ_set0_distinguishing_id(req, sm2UserId);
    }

    return X509_REQ_verify(req, pkey);
}

void CryptoUtils::MakeCert(const char *p10_string, char** ppcertData, bool isVerifyCsr)
{
    if(nullptr == p10_string || nullptr == ppcertData) {
        printErr("参数错误");
        return;
    }
    // 读取PKCS#10请求
    BIO_ptr p10_bio(BIO_new_mem_buf(p10_string, -1), BIO_free);
    if (!p10_bio.get()) {
        printErr("Error reading PKCS#10 request.");
        return;
    }
    X509_REQ_ptr req(PEM_read_bio_X509_REQ(p10_bio.get(), nullptr, nullptr, nullptr), &X509_REQ_free);
    if (nullptr == req.get()) {
        printErr("Error loading PKCS#10 request.");
        return;
    }

    // 验证CSR签名
    EVP_PKEY_ptr req_pubkey(X509_REQ_get_pubkey(req.get()), &EVP_PKEY_free);
    if (nullptr == req_pubkey.get()) {
        printErr("Error getting public key from CSR.");
        return;
    }

    int isSM2 = EVP_PKEY_is_a(req_pubkey.get(), "SM2");
    int isRSA = EVP_PKEY_is_a(req_pubkey.get(), "RSA");
    if(true == isVerifyCsr) {
        if(1 == isSM2) {
            ASN1_OCTET_STRING* sm2UserId = ASN1_OCTET_STRING_new();
            if(nullptr != sm2UserId) {
                ASN1_OCTET_STRING_set(sm2UserId, (const unsigned char*)"1234567812345678", 16);
            }
            X509_REQ_set0_distinguishing_id(req.get(), sm2UserId);
        }
        if (X509_REQ_verify(req.get(), req_pubkey.get()) <= 0) {
            printErr("CSR signature verification failed.");
            return;
        }
    }
    X509* pca_cert = nullptr;
    EVP_PKEY* pca_key = nullptr;

    int ret = 0;
    if(1 == isSM2) {
        ret = LoadCACertAndPrikey(m_sm2CertPath.toStdString().c_str(), m_sm2PrivateKeyPath.toStdString().c_str(), &pca_cert, &pca_key);
    } else if(1 == isRSA) {
        ret = LoadCACertAndPrikey(m_rsaCertPath.toStdString().c_str(), m_rsaPrivateKeyPath.toStdString().c_str(), &pca_cert, &pca_key);
    } else {
        printErr("未知公钥类型");
        return ;
    }

    if(0 != ret) {
        printErr("加载根证书失败，请检查config.ini配置文件");
        return;
    }
    X509_ptr ca_cert(pca_cert, &X509_free);
    EVP_PKEY_ptr ca_key(pca_key, &EVP_PKEY_free);

    // 创建新的证书
    X509_ptr new_cert(X509_new(), &X509_free);
    if (nullptr == new_cert) {
        printErr("Error creating new certificate.");
        return;
    }

    // 设置证书的版本
    X509_set_version(new_cert.get(), 2); // 版本3的证书

    // 设置证书的序列号
    ASN1_INTEGER_set(X509_get_serialNumber(new_cert.get()), 2);

    // 设置证书的有效期
    X509_gmtime_adj(X509_get_notBefore(new_cert.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(new_cert.get()), 31536000L); // 有效期一年

    // 从请求中提取公钥
    //req_pubkey = X509_REQ_get_pubkey(req);
    X509_set_pubkey(new_cert.get(), req_pubkey.get());
    //EVP_PKEY_free(req_pubkey);

    // 从请求中提取主体名并设置到新证书中
    X509_NAME *subject_name = X509_REQ_get_subject_name(req.get());
    X509_set_subject_name(new_cert.get(), subject_name);

    // 设置签发者名
    X509_NAME *issuer_name = X509_get_subject_name(pca_cert);
    X509_set_issuer_name(new_cert.get(), issuer_name);

    // 签发证书
    if (!X509_sign(new_cert.get(), pca_key, isSM2?EVP_sm3():EVP_sha256())) {
        printErr("Error signing certificate.");
        return;
    }

    int certDataSize = 0;
    char* pcertData = nullptr;
    ret = x509CertificateToPEM(new_cert.get(), pcertData, &certDataSize);
    if(0 != ret || certDataSize <= 0) {
        printErr("x509 to pem err");
        return;
    }

    pcertData = new char[certDataSize + 1];
    ret = x509CertificateToPEM(new_cert.get(), pcertData, &certDataSize);
    *ppcertData = pcertData;
}

int CryptoUtils::x509CertificateToPEM(X509 *cert, char* outData, int* outDataSize)
{
    if (nullptr == cert || nullptr == outDataSize) {
        printErr("无效的参数");
        return -1;
    }

    BIO_ptr bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio) {
        printErr("错误：创建BIO失败");
        return -1;
    }

    // 写入证书数据
    if (!PEM_write_bio_X509(bio.get(), cert)) {
        printErr("错误：写入X509证书数据失败");
        return -1;
    }

    // 获取内存缓冲区
    BUF_MEM *buf_mem = nullptr;
    BIO_get_mem_ptr(bio.get(), &buf_mem);
    if (!buf_mem || buf_mem->length == 0) {
        printErr("错误：获取内存缓冲区失败");
        return -1;
    }

    if(*outDataSize >= buf_mem->length && nullptr != outData) {
        memcpy(outData, buf_mem->data, buf_mem->length);
    }

    *outDataSize = buf_mem->length;
    return 0;
}

void CryptoUtils::ParsePubkey(EVP_PKEY *pkey)
{
    int isSM2 = EVP_PKEY_is_a(pkey, "sm2");
    int isRSA = EVP_PKEY_is_a(pkey, "rsa");

    unsigned char* pubKeyBuff = nullptr;
    int pubLen = i2d_PUBKEY(pkey, &pubKeyBuff);
    printLog("公钥DER:");
    printLog(toHex(pubKeyBuff, pubLen));

    if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA || 1 == isRSA)
    {
        BIGNUM* pbn = nullptr;
        BIGNUM* pbe = nullptr;
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &pbn);
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &pbe);
        if(nullptr == pbn || nullptr == pbe) {
            return;
        }
        char *hex_str_n = BN_bn2hex(pbn);
        printLog("N:");
        printLog(hex_str_n);

        char *hex_str_e = BN_bn2hex(pbe);
        printLog("E:");
        printLog(hex_str_e);
    }
    else if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC || EVP_PKEY_base_id(pkey) == EVP_PKEY_SM2 || 1 == isSM2)
    {
        BIGNUM* pbx = nullptr;
        BIGNUM* pby = nullptr;
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &pbx);
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &pby);

        char *x_hex = BN_bn2hex(pbx);
        char *y_hex = BN_bn2hex(pby);
        printLog("X:");
        printLog(x_hex);
        printLog("Y:");
        printLog(y_hex);
    }
    else
    {
        printErr("Unsupported key type.\n");
        return;
    }
}
void CryptoUtils::ParseP10(const unsigned char *p10_data, int p10_len)
{
    OSSL_PROVIDER *provider = OSSL_PROVIDER_load(nullptr, "default");
    if (!provider) {
        printErr("Failed to load default provider\n");
        ERR_print_errors_fp(stderr);
        return;
    }

    BIO_ptr bio(BIO_new_mem_buf(p10_data, p10_len), BIO_free);
    if (!bio.get()) {
        printErr("Error creating BIO.\n");
        return ;
    }

    X509_REQ_ptr req(PEM_read_bio_X509_REQ(bio.get(), nullptr, nullptr, nullptr), X509_REQ_free);
    if (!req.get()) {
        printErr("Error reading the certificate request.\n");
        return ;
    }

    EVP_PKEY* pkey = X509_REQ_get0_pubkey(req.get());
    if (nullptr == pkey) {
        printErr("Error getting public key from request.");
        return ;
    }
    // 输出公钥信息
    ParsePubkey(pkey);

    //签名值
    const ASN1_BIT_STRING *signature = nullptr;
    X509_REQ_get0_signature(req.get(), &signature, nullptr);
    printLog("签名值:");
    printLog(QByteArray((const char*)signature->data, signature->length).toHex().toUpper());

    int pkey_id = EVP_PKEY_get_id(pkey);
    int isSM2 = EVP_PKEY_is_a(pkey, "SM2");
    if(EVP_PKEY_SM2 == pkey_id || EVP_PKEY_EC == pkey_id || 1 == isSM2) {
        const unsigned char* sig_data = signature->data;
        ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &sig_data, signature->length);
        if(nullptr == sig) {
            printLog("解析签名值失败");
            return;
        }
        const BIGNUM* r = nullptr;
        const BIGNUM* s = nullptr;
        ECDSA_SIG_get0(sig, &r, &s);
        const char* str_r = BN_bn2hex(r);
        const char* str_s = BN_bn2hex(s);
        printLog("R:");
        printLog(str_r);
        printLog("S:");
        printLog(str_s);
    }

    //原文
    unsigned char *buf = nullptr;
    int len = i2d_re_X509_REQ_tbs(req.get(), &buf);
    printLog("原文：");
    printLog(toHex(buf, len));
    if (len > 0) {
        OPENSSL_free(buf);
    }

    int nid = X509_REQ_get_signature_nid(req.get());
    const char *alg_name = OBJ_nid2ln(nid);
    const char *alg_sn = OBJ_nid2sn(nid);
    printLog(QString("HASH算法:%1").arg(alg_sn));
    printLog(alg_name);
    return ;
}

unsigned char* CryptoUtils::remove_pkcs1_padding(const unsigned char *data, size_t data_len, size_t *out_len)
{
    if (data_len < 11 || data[0] != 0x00 || data[1] != 0x01) {
        printErr("Invalid PKCS#1 padding.\n");
        return nullptr;
    }

    // Find the end of padding (0x00 byte)
    size_t i;
    for (i = 2; i < data_len; i++) {
        if (data[i] == 0x00)
            break;
    }

    if (i == data_len) {
        printErr("Padding end not found.\n");
        return nullptr;
    }

    // Data starts after the 0x00 byte
    size_t padding_len = i + 1;
    *out_len = data_len - padding_len;

    unsigned char *out_data = (unsigned char *)malloc(*out_len);
    if (!out_data) {
        printErr("Memory allocation error.\n");
        return nullptr;
    }
    memcpy(out_data, data + padding_len, *out_len);
    return out_data;
}

bool CryptoUtils::sm2_verify(EVP_PKEY* pkey, const unsigned char* der_sign, size_t der_sig_len,
                             const unsigned char* dgst, size_t dgst_len)
{
    if(nullptr == pkey || nullptr == der_sign) {
        return false;
    }

    //创建一个密钥上下文
    EVP_PKEY_CTX* key_ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if(nullptr == key_ctx) {
        printErr("EVP_PKEY_CTX_new err");
        return false;
    }

    EVP_PKEY_verify_init(key_ctx);
    int rv = EVP_PKEY_verify(key_ctx, der_sign, der_sig_len, dgst, dgst_len);
    if(1 == rv) {
        printLog("验签成功");
    } else {
        printLog("验签失败");
    }
    return 1 == rv?true:false;
}

void CryptoUtils::printLog(const QString& msg)
{
    logCallback(msg, Qt::black);
}

void CryptoUtils::printErr(const QString & msg)
{
    logCallback(msg, Qt::red);
}

QString CryptoUtils::toHex(const unsigned char* data, int len)
{
    QByteArray hexData((const char* )data, len);
    return hexData.toHex().toUpper();
}
