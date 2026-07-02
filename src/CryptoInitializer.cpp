
#include "../include/CryptoInitializer.h"

#include <Poco/Crypto/Crypto.h>

CryptoInitializer::CryptoInitializer() {
    // Inicializa a biblioteca de criptografia da Poco
    Poco::Crypto::initializeCrypto();

    // Registra a função de finalização da biblioteca de criptografia da Poco
    std::atexit([]() { Poco::Crypto::uninitializeCrypto(); });
}

void CryptoInitializer::ensure() {
    static CryptoInitializer instance;

    // Evita warnings de variável não utilizada
    (void)instance;
}

