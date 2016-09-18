#include <cstdlib>
#include <syscall.h>
#include <utils/crypto/crypto.h>

using namespace std;

Crypto::Crypto() : aesEncryptCtx(NULL), aesDecryptCtx(NULL), aesKey(NULL), aesIv(NULL), rsaRemotePubKey(NULL), rsaLocalPubKey(NULL), rsaLocalPriKey(NULL) {

}

Crypto::~Crypto() {
    this->FreeAes();
    this->FreeRsa();
    //CRYPTO_cleanup_all_ex_data();
}

int Crypto::InitAes() {
    aesEncryptCtx = EVP_CIPHER_CTX_new();
    aesDecryptCtx = EVP_CIPHER_CTX_new();
    if (NULL == aesEncryptCtx || NULL == aesDecryptCtx)
        return FAILURE;

    EVP_CIPHER_CTX_init(aesEncryptCtx);
    EVP_CIPHER_CTX_init(aesDecryptCtx);

    aesKey = (unsigned char*) malloc(AES_KEYLEN / 16);
    aesIv = (unsigned char*) malloc(AES_KEYLEN / 16);

    memset(aesKey, 0, AES_KEYLEN / 16);
    memset(aesIv, 0, AES_KEYLEN / 16);

    return SUCCESS;
}

int Crypto::InitRsa() {
    rsaRemotePubKey = RSA_new();
    rsaLocalPubKey = RSA_new();
    rsaLocalPriKey = RSA_new();

    return SUCCESS;
}

void Crypto::FreeAes() {
    if (NULL != aesEncryptCtx) {
        EVP_CIPHER_CTX_cleanup(aesEncryptCtx);
        EVP_CIPHER_CTX_free(aesEncryptCtx);
        aesEncryptCtx = NULL;
    }
    if (NULL != aesDecryptCtx) {
        EVP_CIPHER_CTX_cleanup(aesDecryptCtx);
        EVP_CIPHER_CTX_free(aesDecryptCtx);
        aesDecryptCtx = NULL;
    }
    if (NULL != aesKey) {
        free(aesKey);
        aesKey = NULL;
    }
    if (NULL != aesIv) {
        free(aesIv);
        aesIv = NULL;
    }
}

void Crypto::FreeRsa() {
    if (NULL != rsaRemotePubKey) {
        RSA_free(rsaRemotePubKey);
        rsaRemotePubKey = NULL;
    }
    if (NULL != rsaLocalPubKey) {
        RSA_free(rsaLocalPubKey);
        rsaLocalPubKey = NULL;
    }
    if (NULL != rsaLocalPriKey) {
        RSA_free(rsaLocalPriKey);
        rsaLocalPriKey = NULL;
    }
}

int Crypto::AesEncrypt(const unsigned char* msg, size_t msgLen, unsigned char** encMsg) {
    if (NULL == aesEncryptCtx || NULL == aesKey || NULL == aesIv)
        return FAILURE;

    size_t blockLen = 0;
    size_t encMsgLen = 0;

    *encMsg = (unsigned char*) malloc(msgLen + AES_BLOCK_SIZE);

    if (!EVP_EncryptInit_ex(aesEncryptCtx, EVP_aes_128_cbc(), NULL, aesKey, aesIv))
        return FAILURE;

    if (!EVP_EncryptUpdate(aesEncryptCtx, *encMsg, (int*) &blockLen, (unsigned char*) msg, (int) msgLen))
        return FAILURE;

    encMsgLen += blockLen;

    if (!EVP_EncryptFinal_ex(aesEncryptCtx, *encMsg + encMsgLen, (int*) &blockLen))
        return FAILURE;

    return (int) (encMsgLen + blockLen);
}

int Crypto::AesDecrypt(unsigned char* encMsg, size_t encMsgLen, unsigned char** decMsg) {
    if (NULL == aesEncryptCtx || NULL == aesKey || NULL == aesIv)
        return FAILURE;

    size_t decLen = 0;
    size_t blockLen = 0;

    *decMsg = (unsigned char*) malloc(encMsgLen);

    if (!EVP_DecryptInit_ex(aesDecryptCtx, EVP_aes_128_cbc(), NULL, aesKey, aesIv))
        return FAILURE;

    if (!EVP_DecryptUpdate(aesDecryptCtx, *decMsg, (int*) &blockLen, encMsg, (int) encMsgLen))
        return FAILURE;
    decLen += blockLen;

    if (!EVP_DecryptFinal_ex(aesDecryptCtx, *decMsg + decLen, (int*) &blockLen))
        return FAILURE;
    decLen += blockLen;

    return (int) decLen;
}

int Crypto::SetAesKey(unsigned char* aesKey, size_t aesKeyLen) {
    if ((int) aesKeyLen != AES_KEYLEN / 16)
        return FAILURE;

    memcpy(this->aesKey, aesKey, AES_KEYLEN / 16);

    return SUCCESS;
}

int Crypto::SetAesIv(unsigned char* aesIv, size_t aesIvLen) {
    if ((int) aesIvLen != AES_KEYLEN / 16)
        return FAILURE;

    memcpy(this->aesIv, aesIv, AES_KEYLEN / 16);

    return SUCCESS;
}

int Crypto::RsaEncrypt(const unsigned char* msg, size_t msgLen, unsigned char** encMsg) {
    if (NULL == rsaRemotePubKey)
        return FAILURE;

    size_t nLen = (size_t) RSA_size(rsaRemotePubKey);
    *encMsg = (unsigned char*) malloc(nLen + 1);
    memset(*encMsg, 0, nLen + 1);

    return RSA_public_encrypt((int) msgLen, msg, *encMsg, rsaRemotePubKey, RSA_PKCS1_PADDING);
}

int Crypto::RsaDecrypt(const unsigned char* encMsg, size_t encMsgLen, unsigned char** decMsg) {
    if (NULL == rsaLocalPriKey)
        return FAILURE;

    size_t nLen = (size_t) RSA_size(rsaLocalPriKey);
    *decMsg = (unsigned char*) malloc(nLen + 1);
    memset(*decMsg, 0, nLen + 1);

    return RSA_private_decrypt((int) encMsgLen, encMsg, *decMsg, rsaLocalPriKey, RSA_PKCS1_PADDING);
}

int Crypto::SetRsaLocalPubKey(unsigned char* key, size_t keyLen) {
    BIO* bio = BIO_new(BIO_s_mem());

    if (BIO_write(bio, key, (int) keyLen) != (int) keyLen)
        return FAILURE;

    if (NULL == PEM_read_bio_RSA_PUBKEY(bio, &rsaLocalPubKey, NULL, NULL))
        return FAILURE;

    BIO_free_all(bio);
}

int Crypto::SetRsaLocalPriKey(unsigned char* key, size_t keyLen) {
    BIO* bio = BIO_new(BIO_s_mem());

    if (BIO_write(bio, key, (int) keyLen) != (int) keyLen)
        return FAILURE;

    PEM_read_bio_RSAPrivateKey(bio, &rsaLocalPriKey, NULL, NULL);
    BIO_free_all(bio);
}

int Crypto::SetRsaRemotePubKey(unsigned char* key, size_t keyLen) {
    BIO* bio = BIO_new(BIO_s_mem());

    if (BIO_write(bio, key, (int) keyLen) != (int) keyLen)
        return FAILURE;

    if (NULL == PEM_read_bio_RSA_PUBKEY(bio, &rsaRemotePubKey, NULL, NULL))
        return FAILURE;

    BIO_free_all(bio);
}

int Crypto::WriteKeyToFile(FILE* fd, int key) {
    switch (key) {
        case KEY_REMOTE_PUB:
            if (!PEM_write_RSA_PUBKEY(fd, rsaRemotePubKey))
                return FAILURE;
            break;
        case KEY_LOCAL_PUB:
            if (!PEM_write_RSA_PUBKEY(fd, rsaLocalPubKey))
                return FAILURE;
            break;
        case KEY_LOCAL_PRI:
            if (!PEM_write_RSAPrivateKey(fd, rsaLocalPriKey, NULL, NULL, 0, 0, NULL))
                return FAILURE;
            break;
        case KEY_AES:
            fwrite(aesKey, 1, AES_KEYLEN, fd);
            break;
        case KEY_AES_IV:
            fwrite(aesIv, 1, AES_KEYLEN, fd);
            break;
        default:
            return FAILURE;
    }

    return SUCCESS;
}

int Crypto::GenerateAesIv() {
    if (aesKey == NULL || aesIv == NULL)
        return FAILURE;

    if (RAND_bytes(aesKey, AES_KEYLEN / 16) == 0)
        return FAILURE;

    if (RAND_bytes(aesIv, AES_KEYLEN / 16) == 0)
        return FAILURE;

    return SUCCESS;
}
