//
// Created by leiwenbin on 16-7-1.
//

#include <utils/uuid/uuid_convert.h>

UUIDConvert::UUIDConvert() {

}

UUIDConvert::~UUIDConvert() {

}

UUID_t UUIDConvert::GenerateUUID() {
    UUID_t uuid = {0};
    uuid_generate(reinterpret_cast<unsigned char*>(&uuid));
    return uuid;
}

UUID_t UUIDConvert::String2UUID(std::string str_uuid) {
    UUID_t uuid = {0};
    for (int i = 0; i < 16; ++i) {
        char szHex[3] = {0};
        memcpy(szHex, &(str_uuid[i * 2]), 1);
        memcpy(szHex + 1, &(str_uuid[i * 2 + 1]), 1);
        char* szOut = NULL;
        long value = strtol(szHex, &szOut, 16);
        uuid.uuid[i] = (unsigned char) value;
    }
    return uuid;
}

std::string UUIDConvert::UUID2StringLittle(UUID_t& uuid) {
    char szBuf[64] = {0};
    snprintf(szBuf, sizeof(szBuf), "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X", uuid.uuid[0], uuid.uuid[1], uuid.uuid[2], uuid.uuid[3], uuid.uuid[4], uuid.uuid[5], uuid.uuid[6],
             uuid.uuid[7], uuid.uuid[8], uuid.uuid[9], uuid.uuid[10], uuid.uuid[11], uuid.uuid[12], uuid.uuid[13], uuid.uuid[14], uuid.uuid[15]);
    return std::string(szBuf);
}

std::string UUIDConvert::UUID2StringBig(UUID_t& uuid) {
    char szBuf[64] = {0};
    snprintf(szBuf, sizeof(szBuf), "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X", uuid.uuid[15], uuid.uuid[14], uuid.uuid[13], uuid.uuid[12], uuid.uuid[11], uuid.uuid[10], uuid.uuid[9],
             uuid.uuid[8], uuid.uuid[7], uuid.uuid[6], uuid.uuid[5], uuid.uuid[4], uuid.uuid[3], uuid.uuid[2], uuid.uuid[1], uuid.uuid[0]);
    return std::string(szBuf);
}
