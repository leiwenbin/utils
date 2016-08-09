#include <cstdlib>
#include <syscall.h>
#include <utils/crypto/crypto.h>

using namespace std;

Crypto::Crypto() {
    localKeypair = NULL;
    remoteKeypair = NULL;
    rsaEncryptCtx = NULL;
    rsaDecryptCtx = NULL;
    aesEncryptCtx = NULL;
    aesDecryptCtx = NULL;
    aesKey = NULL;
    aesIV = NULL;
    rsaLocalePubKey = NULL;
    rsaLocalePriKey = NULL;
}

Crypto::Crypto(unsigned char* szRemotePubKey, size_t uiRemotePubKeyLen) {
    localKeypair = NULL;
    remoteKeypair = NULL;
    rsaEncryptCtx = NULL;
    rsaDecryptCtx = NULL;
    aesEncryptCtx = NULL;
    aesDecryptCtx = NULL;
    aesKey = NULL;
    aesIV = NULL;
    rsaLocalePubKey = NULL;
    rsaLocalePriKey = NULL;

#ifdef PSUEDO_CLIENT
    GenTestClientKey();
#endif

    SetRemotePubKey(szRemotePubKey, uiRemotePubKeyLen);
}

Crypto::~Crypto() {
    if (NULL != remoteKeypair)
        EVP_PKEY_free(remoteKeypair);

    if (NULL != rsaEncryptCtx) {
        EVP_CIPHER_CTX_cleanup(rsaEncryptCtx);
        EVP_CIPHER_CTX_free(rsaEncryptCtx);
    }

    if (NULL != rsaDecryptCtx) {
        EVP_CIPHER_CTX_cleanup(rsaDecryptCtx);
        EVP_CIPHER_CTX_free(rsaDecryptCtx);
    }

    if (NULL != aesEncryptCtx) {
        EVP_CIPHER_CTX_cleanup(aesEncryptCtx);
        EVP_CIPHER_CTX_free(aesEncryptCtx);
    }

    if (NULL != aesDecryptCtx) {
        EVP_CIPHER_CTX_cleanup(aesDecryptCtx);
        EVP_CIPHER_CTX_free(aesDecryptCtx);
    }

    if (NULL != aesKey)
        free(aesKey);

    if (NULL != aesIV)
        free(aesIV);

    if (NULL != rsaLocalePubKey)
        RSA_free(rsaLocalePubKey);

    if (NULL != rsaLocalePriKey)
        RSA_free(rsaLocalePriKey);

    CRYPTO_cleanup_all_ex_data();
}

int Crypto::RsaEncrypt(const unsigned char* msg, size_t msgLen, unsigned char** encMsg, unsigned char** ek, size_t* ekl, unsigned char** iv, size_t* ivl) {
    size_t encMsgLen = 0;
    size_t blockLen = 0;

    *ek = (unsigned char*) malloc(EVP_PKEY_size(remoteKeypair));
    *iv = (unsigned char*) malloc(EVP_MAX_IV_LENGTH);
    if (*ek == NULL || *iv == NULL) return FAILURE;
    *ivl = EVP_MAX_IV_LENGTH;

    *encMsg = (unsigned char*) malloc(msgLen + EVP_MAX_IV_LENGTH);

    if (!EVP_SealInit(rsaEncryptCtx, EVP_aes_256_cbc(), ek, (int*) ekl, *iv, &remoteKeypair, 1))
        return FAILURE;

    if (!EVP_SealUpdate(rsaEncryptCtx, *encMsg + encMsgLen, (int*) &blockLen, msg, (int) msgLen))
        return FAILURE;
    encMsgLen += blockLen;

    if (!EVP_SealFinal(rsaEncryptCtx, *encMsg + encMsgLen, (int*) &blockLen))
        return FAILURE;

    encMsgLen += blockLen;

    return (int) encMsgLen;
}

int Crypto::RsaDecrypt(unsigned char* encMsg, size_t encMsgLen, unsigned char* ek, size_t ekl, unsigned char* iv, size_t ivl, unsigned char** decMsg) {
    size_t decLen = 0;
    size_t blockLen = 0;
    EVP_PKEY* key;

    *decMsg = (unsigned char*) malloc(encMsgLen + ivl);

#ifdef PSUEDO_CLIENT
    key = remoteKeypair;
#else
    key = localKeypair;
#endif

    if (!EVP_OpenInit(rsaDecryptCtx, EVP_aes_256_cbc(), ek, (int) ekl, iv, key))
        return FAILURE;

    if (!EVP_OpenUpdate(rsaDecryptCtx, *decMsg + decLen, (int*) &blockLen, encMsg, (int) encMsgLen))
        return FAILURE;
    decLen += blockLen;

    if (!EVP_OpenFinal(rsaDecryptCtx, *decMsg + decLen, (int*) &blockLen))
        return FAILURE;

    decLen += blockLen;

    return (int) decLen;
}

int Crypto::AesEncrypt(const unsigned char* msg, size_t msgLen, unsigned char** encMsg) {
    size_t blockLen = 0;
    size_t encMsgLen = 0;

    //*encMsg = (unsigned char*) malloc(((msgLen - 1 ) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE);
    *encMsg = (unsigned char*) malloc(msgLen + AES_BLOCK_SIZE);

    if (!EVP_EncryptInit_ex(aesEncryptCtx, EVP_aes_128_cbc(), NULL, aesKey, aesIV))
        return FAILURE;

    if (!EVP_EncryptUpdate(aesEncryptCtx, *encMsg, (int*) &blockLen, (unsigned char*) msg, (int) msgLen))
        return FAILURE;

    encMsgLen += blockLen;

    if (!EVP_EncryptFinal_ex(aesEncryptCtx, *encMsg + encMsgLen, (int*) &blockLen))
        return FAILURE;

    return (int) (encMsgLen + blockLen);
}

int Crypto::AesDecrypt(unsigned char* encMsg, size_t encMsgLen, unsigned char** decMsg) {
    size_t decLen = 0;
    size_t blockLen = 0;

    *decMsg = (unsigned char*) malloc(encMsgLen);

    if (!EVP_DecryptInit_ex(aesDecryptCtx, EVP_aes_128_cbc(), NULL, aesKey, aesIV))
        return FAILURE;

    if (!EVP_DecryptUpdate(aesDecryptCtx, *decMsg, (int*) &blockLen, encMsg, (int) encMsgLen))
        return FAILURE;
    decLen += blockLen;

    if (!EVP_DecryptFinal_ex(aesDecryptCtx, *decMsg + decLen, (int*) &blockLen))
        return FAILURE;
    decLen += blockLen;

    return (int) decLen;
}

int Crypto::WriteKeyToFile(FILE* fd, int key) {
    switch (key) {
        case KEY_SERVER_PRI:
            if (!PEM_write_PrivateKey(fd, localKeypair, NULL, NULL, 0, 0, NULL))
                return FAILURE;
            break;

        case KEY_SERVER_PUB:
            if (!PEM_write_PUBKEY(fd, localKeypair))
                return FAILURE;
            break;

        case KEY_CLIENT_PRI:
            if (!PEM_write_PrivateKey(fd, remoteKeypair, NULL, NULL, 0, 0, NULL))
                return FAILURE;
            break;

        case KEY_CLIENT_PUB:
            if (!PEM_write_PUBKEY(fd, remoteKeypair))
                return FAILURE;
            break;

        case KEY_LOCALE_PUB:
            if (!PEM_write_RSA_PUBKEY(fd, rsaLocalePubKey))
                return FAILURE;
            break;

        case KEY_LOCALE_PRI:
            if (!PEM_write_RSAPrivateKey(fd, rsaLocalePriKey, NULL, NULL, 0, 0, NULL))
                return FAILURE;
            break;

        case KEY_AES:
            fwrite(aesKey, 1, AES_KEYLEN, fd);
            break;

        case KEY_AES_IV:
            fwrite(aesIV, 1, AES_KEYLEN, fd);
            break;

        default:
            return FAILURE;
    }

    return SUCCESS;
}

int Crypto::GetRemotePubKey(unsigned char** pubKey) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, remoteKeypair);

    int pubKeyLen = BIO_pending(bio);
    *pubKey = (unsigned char*) malloc(pubKeyLen);

    BIO_read(bio, *pubKey, pubKeyLen);

    // Insert the NUL terminator
    (*pubKey)[pubKeyLen - 1] = '\0';

    BIO_free_all(bio);

    return pubKeyLen;
}

int Crypto::SetRemotePubKey(unsigned char* pubKey, size_t pubKeyLen) {
    BIO* bio = BIO_new(BIO_s_mem());

    if (BIO_write(bio, pubKey, (int) pubKeyLen) != (int) pubKeyLen)
        return FAILURE;

    PEM_read_bio_PUBKEY(bio, &remoteKeypair, NULL, NULL);
    BIO_free_all(bio);

    return SUCCESS;
}

int Crypto::GetRemotePriKey(unsigned char** priKey) {
    BIO* bio = BIO_new(BIO_s_mem());

    PEM_write_bio_PrivateKey(bio, remoteKeypair, NULL, NULL, 0, 0, NULL);

    int priKeyLen = BIO_pending(bio);
    *priKey = (unsigned char*) malloc(priKeyLen + 1);

    BIO_read(bio, *priKey, priKeyLen);

    // Insert the NUL terminator
    (*priKey)[priKeyLen] = '\0';

    BIO_free_all(bio);

    return priKeyLen;
}

int Crypto::SetRemotePriKey(unsigned char* priKey, size_t priKeyLen) {
    BIO* bio = BIO_new(BIO_s_mem());

    if (BIO_write(bio, priKey, (int) priKeyLen) != (int) priKeyLen)
        return FAILURE;

    PEM_read_bio_PrivateKey(bio, &remoteKeypair, NULL, NULL);
    BIO_free_all(bio);

    return SUCCESS;
}

int Crypto::GetLocalPubKey(unsigned char** pubKey) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, localKeypair);

    int pubKeyLen = BIO_pending(bio);
    *pubKey = (unsigned char*) malloc(pubKeyLen);

    BIO_read(bio, *pubKey, pubKeyLen);

    // Insert the NUL terminator
    (*pubKey)[pubKeyLen - 1] = '\0';

    BIO_free_all(bio);

    return pubKeyLen;
}

int Crypto::SetLocalPubKey(unsigned char* pubKey, size_t pubKeyLen) {
    BIO* bio = BIO_new(BIO_s_mem());

    if (BIO_write(bio, pubKey, (int) pubKeyLen) != (int) pubKeyLen)
        return FAILURE;

    PEM_read_bio_PUBKEY(bio, &localKeypair, NULL, NULL);
    BIO_free_all(bio);

    return SUCCESS;
}

int Crypto::GetLocalPriKey(unsigned char** priKey) {
    BIO* bio = BIO_new(BIO_s_mem());

    PEM_write_bio_PrivateKey(bio, localKeypair, NULL, NULL, 0, 0, NULL);

    int priKeyLen = BIO_pending(bio);
    *priKey = (unsigned char*) malloc(priKeyLen + 1);

    BIO_read(bio, *priKey, priKeyLen);

    // Insert the NUL terminator
    (*priKey)[priKeyLen] = '\0';

    BIO_free_all(bio);

    return priKeyLen;
}

int Crypto::SetLocalPriKey(unsigned char* priKey, size_t priKeyLen) {
    BIO* bio = BIO_new(BIO_s_mem());

    if (BIO_write(bio, priKey, (int) priKeyLen) != (int) priKeyLen)
        return FAILURE;

    PEM_read_bio_PrivateKey(bio, &localKeypair, NULL, NULL);
    BIO_free_all(bio);

    return SUCCESS;
}

int Crypto::GetAESKey(unsigned char** aesKey) {
    *aesKey = this->aesKey;
    return AES_KEYLEN / 16;
}

int Crypto::SetAESKey(unsigned char* aesKey, size_t aesKeyLen) {
    // Ensure the new key is the proper size
    if ((int) aesKeyLen != AES_KEYLEN / 16)
        return FAILURE;

    memcpy(this->aesKey, aesKey, AES_KEYLEN / 16);

    return SUCCESS;
}

int Crypto::GetAESIv(unsigned char** aesIV) {
    *aesIV = this->aesIV;
    return AES_KEYLEN / 16;
}

int Crypto::SetAESIv(unsigned char* aesIV, size_t aesIVLen) {
    // Ensure the new IV is the proper size
    if ((int) aesIVLen != AES_KEYLEN / 16)
        return FAILURE;

    memcpy(this->aesIV, aesIV, AES_KEYLEN / 16);

    return SUCCESS;
}

int Crypto::InitAes() {
    // Initalize contexts
    aesEncryptCtx = (EVP_CIPHER_CTX*) malloc(sizeof(EVP_CIPHER_CTX));
    aesDecryptCtx = (EVP_CIPHER_CTX*) malloc(sizeof(EVP_CIPHER_CTX));

    if (aesEncryptCtx == NULL || aesDecryptCtx == NULL)
        return FAILURE;

    EVP_CIPHER_CTX_init(aesEncryptCtx);
    EVP_CIPHER_CTX_init(aesDecryptCtx);

    // Init AES
    aesKey = (unsigned char*) malloc(AES_KEYLEN / 8);
    aesIV = (unsigned char*) malloc(AES_KEYLEN / 8);

    if (aesKey == NULL || aesIV == NULL)
        return FAILURE;

    // For the AES key we have the option of using a PBKDF (password-baswed key derivation formula)
    // or just using straight random data for the key and IV. Depending on your use case, you will
    // want to pick one or another.
#ifdef USE_PBKDF
    // Get some random data to use as the AES pass and salt
    unsigned char* aesPass = (unsigned char*) malloc(AES_KEYLEN / 8);
    unsigned char* aesSalt = (unsigned char*) malloc(8);

    if (aesPass == NULL || aesSalt == NULL)
        return FAILURE;

    if(RAND_bytes(aesPass, AES_KEYLEN/8) == 0)
        return FAILURE;

    if(RAND_bytes(aesSalt, 8) == 0)
        return FAILURE;

    if(EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), aesSalt, aesPass, AES_KEYLEN/8, AES_ROUNDS, aesKey, aesIV) == 0)
        return FAILURE;

    free(aesPass);
    free(aesSalt);
#else
    if (RAND_bytes(aesKey, AES_KEYLEN / 8) == 0)
        return FAILURE;

    if (RAND_bytes(aesIV, AES_KEYLEN / 8) == 0)
        return FAILURE;
#endif

    return SUCCESS;
}

int Crypto::InitRsa() {
    // Initalize contexts
    rsaEncryptCtx = (EVP_CIPHER_CTX*) malloc(sizeof(EVP_CIPHER_CTX));
    rsaDecryptCtx = (EVP_CIPHER_CTX*) malloc(sizeof(EVP_CIPHER_CTX));

    if (rsaEncryptCtx == NULL || rsaDecryptCtx == NULL)
        return FAILURE;

    // Init these here to make valgrind happy
    EVP_CIPHER_CTX_init(rsaEncryptCtx);
    EVP_CIPHER_CTX_init(rsaDecryptCtx);

    return SUCCESS;
}

int Crypto::GenTestServerKey() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        return FAILURE;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEYLEN) <= 0) {
        return FAILURE;
    }

    if (EVP_PKEY_keygen(ctx, &localKeypair) <= 0) {
        return FAILURE;
    }

    EVP_PKEY_CTX_free(ctx);
}

int Crypto::GenTestClientKey() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        return FAILURE;

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEYLEN) <= 0)
        return FAILURE;

    if (EVP_PKEY_keygen(ctx, &remoteKeypair) <= 0)
        return FAILURE;

    EVP_PKEY_CTX_free(ctx);

    return SUCCESS;
}

int Crypto::RsaEncryptNew(unsigned char* pubKey, size_t pubKeyLen, const unsigned char* msg, size_t msgLen, unsigned char** encMsg) {
    rsaLocalePubKey = RSA_new();
    BIO* bio = BIO_new(BIO_s_mem());

    if (BIO_write(bio, pubKey, (int) pubKeyLen) != (int) pubKeyLen)
        return FAILURE;

    if (NULL == PEM_read_bio_RSA_PUBKEY(bio, &rsaLocalePubKey, NULL, NULL))
        return FAILURE;

    BIO_free_all(bio);

    int nLen = RSA_size(rsaLocalePubKey);
    *encMsg = new unsigned char[nLen + 1];
    memset(*encMsg, 0, nLen);

    return  RSA_public_encrypt((int) msgLen, msg, *encMsg, rsaLocalePubKey, RSA_PKCS1_PADDING);
}

int Crypto::RsaDecryptNew(unsigned char* priKey, size_t priKeyLen, const unsigned char* encMsg, size_t encMsgLen, unsigned char** decMsg) {
    rsaLocalePriKey = RSA_new();
    BIO* bio = BIO_new(BIO_s_mem());

    if (BIO_write(bio, priKey, (int) priKeyLen) != (int) priKeyLen)
        return FAILURE;

    PEM_read_bio_RSAPrivateKey(bio, &rsaLocalePriKey, NULL, NULL);
    BIO_free_all(bio);

    int nLen = RSA_size(rsaLocalePriKey);
    *decMsg = new unsigned char[nLen + 1];
    memset(*decMsg, 0, nLen);

    return RSA_private_decrypt((int) encMsgLen, encMsg, *decMsg, rsaLocalePriKey, RSA_PKCS1_PADDING);
}
