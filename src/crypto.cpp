#include <cstdlib>
#include <syscall.h>
#include <utils/crypto/crypto.h>

using namespace std;

Crypto::Crypto() : aesEncryptCtx(NULL), aesDecryptCtx(NULL), aesKey(NULL), aesIv(NULL), rsaRemotePubKey(NULL), rsaLocalPubKey(NULL), rsaLocalPriKey(NULL), bits(0), aesInitState(false) {

}

Crypto::~Crypto() {
    this->FreeAes();
    this->FreeRsa();
    //CRYPTO_cleanup_all_ex_data();
}

int Crypto::InitAes() {
    return this->InitAes256(SECURITY_LEVEL::low);
}

int Crypto::InitAes256(SECURITY_LEVEL securityLevel) {
    if (this->aesInitState)
        return FAILURE;

    int keyUnit = 8;
    if (securityLevel == SECURITY_LEVEL::low)
        keyUnit = 16;

    this->aesEncryptCtx = EVP_CIPHER_CTX_new();
    this->aesDecryptCtx = EVP_CIPHER_CTX_new();
    if (NULL == aesEncryptCtx || NULL == this->aesDecryptCtx)
        return FAILURE;

    EVP_CIPHER_CTX_init(this->aesEncryptCtx);
    EVP_CIPHER_CTX_init(this->aesDecryptCtx);

    this->aesKey = (unsigned char*) malloc(AES_KEYLEN / keyUnit);
    this->aesIv = (unsigned char*) malloc(AES_KEYLEN / keyUnit);

    memset(this->aesKey, 0, AES_KEYLEN / keyUnit);
    memset(this->aesIv, 0, AES_KEYLEN / keyUnit);

    this->aesInitState = true;

    return SUCCESS;
}

int Crypto::InitRsa(unsigned int b) {
    this->bits = b;

    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);

    RSA* rsa = RSA_new();
    RSA_generate_key_ex(rsa, this->bits, e, NULL);

    this->rsaLocalPubKey = RSAPublicKey_dup(rsa);
    this->rsaLocalPriKey = RSAPrivateKey_dup(rsa);

    BN_free(e);
    RSA_free(rsa);

    return SUCCESS;
}

void Crypto::FreeAes() {
    if (NULL != this->aesEncryptCtx) {
        EVP_CIPHER_CTX_cleanup(this->aesEncryptCtx);
        EVP_CIPHER_CTX_free(this->aesEncryptCtx);
        this->aesEncryptCtx = NULL;
    }
    if (NULL != this->aesDecryptCtx) {
        EVP_CIPHER_CTX_cleanup(this->aesDecryptCtx);
        EVP_CIPHER_CTX_free(this->aesDecryptCtx);
        this->aesDecryptCtx = NULL;
    }
    if (NULL != this->aesKey) {
        free(this->aesKey);
        this->aesKey = NULL;
    }
    if (NULL != this->aesIv) {
        free(this->aesIv);
        this->aesIv = NULL;
    }
}

void Crypto::FreeRsa() {
    if (NULL != this->rsaRemotePubKey) {
        RSA_free(this->rsaRemotePubKey);
        this->rsaRemotePubKey = NULL;
    }
    if (NULL != this->rsaLocalPubKey) {
        RSA_free(this->rsaLocalPubKey);
        this->rsaLocalPubKey = NULL;
    }
    if (NULL != this->rsaLocalPriKey) {
        RSA_free(this->rsaLocalPriKey);
        this->rsaLocalPriKey = NULL;
    }
}

int Crypto::AesEncrypt(const unsigned char* msg, size_t msgLen, unsigned char** encMsg) {
    return this->AesEncrypt256(msg, msgLen, encMsg, SECURITY_LEVEL::low);
}

int Crypto::AesEncrypt256(const unsigned char* msg, size_t msgLen, unsigned char** encMsg, SECURITY_LEVEL securityLevel) {
    if (NULL == this->aesEncryptCtx || NULL == this->aesKey || NULL == this->aesIv)
        return FAILURE;

    size_t blockLen = 0;
    size_t encMsgLen = 0;

    *encMsg = (unsigned char*) malloc(msgLen + AES_BLOCK_SIZE);

    const EVP_CIPHER* evpCipher = EVP_aes_256_cbc();
    if (securityLevel == SECURITY_LEVEL::low)
        evpCipher = EVP_aes_128_cbc();

    if (!EVP_EncryptInit(this->aesEncryptCtx, evpCipher, this->aesKey, this->aesIv))
        return FAILURE;

    if (!EVP_EncryptUpdate(this->aesEncryptCtx, *encMsg, (int*) &blockLen, (unsigned char*) msg, (int) msgLen))
        return FAILURE;

    encMsgLen += blockLen;

    if (!EVP_EncryptFinal_ex(this->aesEncryptCtx, *encMsg + encMsgLen, (int*) &blockLen))
        return FAILURE;

    return (int) (encMsgLen + blockLen);
}

int Crypto::AesDecrypt(unsigned char* encMsg, size_t encMsgLen, unsigned char** decMsg) {
    return this->AesDecrypt256(encMsg, encMsgLen, decMsg, SECURITY_LEVEL::low);
}

int Crypto::AesDecrypt256(unsigned char* encMsg, size_t encMsgLen, unsigned char** decMsg, SECURITY_LEVEL securityLevel) {
    if (NULL == this->aesEncryptCtx || NULL == this->aesKey || NULL == this->aesIv)
        return FAILURE;

    size_t decLen = 0;
    size_t blockLen = 0;

    *decMsg = (unsigned char*) malloc(encMsgLen);

    const EVP_CIPHER* evpCipher = EVP_aes_256_cbc();
    if (securityLevel == SECURITY_LEVEL::low)
        evpCipher = EVP_aes_128_cbc();

    if (!EVP_DecryptInit(this->aesDecryptCtx, evpCipher, this->aesKey, this->aesIv))
        return FAILURE;

    if (!EVP_DecryptUpdate(this->aesDecryptCtx, *decMsg, (int*) &blockLen, encMsg, (int) encMsgLen))
        return FAILURE;
    decLen += blockLen;

    if (!EVP_DecryptFinal_ex(this->aesDecryptCtx, *decMsg + decLen, (int*) &blockLen))
        return FAILURE;
    decLen += blockLen;

    return (int) decLen;
}

int Crypto::SetAesKey(unsigned char* aesKey, size_t aesKeyLen) {
    return this->SetAesKey256(aesKey, aesKeyLen, SECURITY_LEVEL::low);
}

int Crypto::SetAesKey256(unsigned char* aesKey, size_t aesKeyLen, SECURITY_LEVEL securityLevel) {
    int keyUnit = 8;
    if (securityLevel == SECURITY_LEVEL::low)
        keyUnit = 16;

    if ((int) aesKeyLen != AES_KEYLEN / keyUnit)
        return FAILURE;

    memcpy(this->aesKey, aesKey, AES_KEYLEN / keyUnit);

    return SUCCESS;
}

int Crypto::SetAesIv(unsigned char* aesIv, size_t aesIvLen) {
    return this->SetAesIv256(aesIv, aesIvLen, SECURITY_LEVEL::low);
}

int Crypto::SetAesIv256(unsigned char* aesIv, size_t aesIvLen, SECURITY_LEVEL securityLevel) {
    int keyUnit = 8;
    if (securityLevel == SECURITY_LEVEL::low)
        keyUnit = 16;

    if ((int) aesIvLen != AES_KEYLEN / keyUnit)
        return FAILURE;

    memcpy(this->aesIv, aesIv, AES_KEYLEN / keyUnit);

    return SUCCESS;
}

int Crypto::RsaEncrypt(const unsigned char* msg, size_t msgLen, unsigned char** encMsg) {
    if (NULL == this->rsaRemotePubKey)
        return FAILURE;

    size_t nLen = (size_t) RSA_size(this->rsaRemotePubKey);
    *encMsg = (unsigned char*) malloc(nLen + 1);
    memset(*encMsg, 0, nLen + 1);

    return RSA_public_encrypt((int) msgLen, msg, *encMsg, this->rsaRemotePubKey, RSA_PKCS1_PADDING);
}

int Crypto::RsaDecrypt(const unsigned char* encMsg, size_t encMsgLen, unsigned char** decMsg) {
    if (NULL == this->rsaLocalPriKey)
        return FAILURE;

    size_t nLen = (size_t) RSA_size(this->rsaLocalPriKey);
    *decMsg = (unsigned char*) malloc(nLen + 1);
    memset(*decMsg, 0, nLen + 1);

    return RSA_private_decrypt((int) encMsgLen, encMsg, *decMsg, this->rsaLocalPriKey, RSA_PKCS1_PADDING);
}

int Crypto::RsaSignByLocalPriKey(const unsigned char* text, unsigned char** signature) {
    if (NULL == text)
        return FAILURE;
    unsigned char sha1[20] = {0};
    unsigned int signature_size;
    SHA1(text, strlen((const char*) text), sha1);
    *signature = (unsigned char*) malloc((size_t) RSA_size(this->rsaLocalPriKey));
    if (1 != RSA_sign(NID_sha1, sha1, 20, *signature, &signature_size, this->rsaLocalPriKey))
        return FAILURE;

    return signature_size;

}

int Crypto::RsaVerifyByLocalPubKey(const unsigned char* text, const unsigned char* signature) {
    if (NULL == text || NULL == signature)
        return FAILURE;
    unsigned char sha1[20] = {0};
    SHA1(text, strlen((const char*) text), sha1);
    if (1 != RSA_verify(NID_sha1, sha1, 20, signature, (unsigned int) RSA_size(this->rsaLocalPubKey), this->rsaLocalPubKey))
        return FAILURE;

    return SUCCESS;
}

int Crypto::RsaVerifyByRemotePubKey(const unsigned char* text, const unsigned char* signature) {
    if (NULL == text || NULL == signature)
        return FAILURE;
    unsigned char sha1[20] = {0};
    SHA1(text, strlen((const char*) text), sha1);
    if (1 != RSA_verify(NID_sha1, sha1, 20, signature, (unsigned int) RSA_size(this->rsaRemotePubKey), this->rsaRemotePubKey))
        return FAILURE;

    return SUCCESS;
}

int Crypto::SetRsaLocalPubKey(unsigned char* key, size_t keyLen) {
    BIO* bio = BIO_new(BIO_s_mem());

    if (BIO_write(bio, key, (int) keyLen) != (int) keyLen)
        return FAILURE;

    if (NULL == PEM_read_bio_RSA_PUBKEY(bio, &this->rsaLocalPubKey, NULL, NULL))
        return FAILURE;

    BIO_free_all(bio);
}

int Crypto::SetRsaLocalPriKey(unsigned char* key, size_t keyLen) {
    BIO* bio = BIO_new(BIO_s_mem());

    if (BIO_write(bio, key, (int) keyLen) != (int) keyLen)
        return FAILURE;

    PEM_read_bio_RSAPrivateKey(bio, &this->rsaLocalPriKey, NULL, NULL);
    BIO_free_all(bio);
}

int Crypto::SetRsaRemotePubKey(unsigned char* key, size_t keyLen) {
    this->rsaRemotePubKey = RSA_new();
    BIO* bio = BIO_new(BIO_s_mem());

    if (BIO_write(bio, key, (int) keyLen) != (int) keyLen)
        return FAILURE;

    if (NULL == PEM_read_bio_RSA_PUBKEY(bio, &this->rsaRemotePubKey, NULL, NULL))
        return FAILURE;

    BIO_free_all(bio);
}

int Crypto::WriteKeyToFile(FILE* fd, int key) {
    switch (key) {
        case KEY_REMOTE_PUB:
            if (!PEM_write_RSAPublicKey(fd, this->rsaRemotePubKey))
                return FAILURE;
            break;
        case KEY_LOCAL_PUB:
            if (!PEM_write_RSAPublicKey(fd, this->rsaLocalPubKey))
                return FAILURE;
            break;
        case KEY_LOCAL_PRI:
            if (!PEM_write_RSAPrivateKey(fd, this->rsaLocalPriKey, NULL, NULL, 0, 0, NULL))
                return FAILURE;
            break;
        case KEY_AES:
            fwrite(this->aesKey, 1, AES_KEYLEN, fd);
            break;
        case KEY_AES_IV:
            fwrite(this->aesIv, 1, AES_KEYLEN, fd);
            break;
        default:
            return FAILURE;
    }

    return SUCCESS;
}

int Crypto::GenerateAesIv() {
    if (this->aesKey == NULL || this->aesIv == NULL)
        return FAILURE;

    if (RAND_bytes(this->aesKey, AES_KEYLEN / 8) == 0)
        return FAILURE;

    if (RAND_bytes(this->aesIv, AES_KEYLEN / 8) == 0)
        return FAILURE;

    return SUCCESS;
}

void Crypto::ShowRsa(unsigned char** pub, unsigned char** pri) {
    *pub = (unsigned char*) malloc((size_t) this->bits);
    memset(*pub, 0, (size_t) this->bits);
    BIO* bio_pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio_pub, this->rsaLocalPubKey);
    BIO_read(bio_pub, *pub, this->bits);

    *pri = (unsigned char*) malloc((size_t) this->bits);
    memset(*pri, 0, (size_t) this->bits);
    BIO* bio_pri = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio_pri, this->rsaLocalPriKey, NULL, NULL, 0, 0, NULL);
    BIO_read(bio_pri, *pri, this->bits);

    BIO_free_all(bio_pub);
    BIO_free_all(bio_pri);
}
