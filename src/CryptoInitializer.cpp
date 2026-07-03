
#include "../include/CryptoInitializer.h"

#include <openssl/err.h>

#include <Poco/Crypto/Crypto.h>

CryptoInitializer::CryptoInitializer() {
    // Inicializa a biblioteca de criptografia da Poco
    Poco::Crypto::initializeCrypto();
}

CryptoInitializer::~CryptoInitializer() {
    // Limpa estados de erro do OpenSSL
    OPENSSL_thread_stop();

    // Finaliza a biblioteca de criptografia da Poco
    Poco::Crypto::uninitializeCrypto();
}

void CryptoInitializer::ensure() {
    static CryptoInitializer instance;

    // Evita warnings de variável não utilizada
    (void)instance;
}

