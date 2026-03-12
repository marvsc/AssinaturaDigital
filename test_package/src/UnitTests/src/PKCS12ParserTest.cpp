
#include "../include/PKCS12ParserTest.h"

#include "PKCS12Parser.h"
#include "OpenSSLUtils.h"

#include "../include/AssinaturaDigitalMacros.h"

#include "Data/POCO/PKCS12POCO.h"

#include <cstdlib>

// Registra o suite de testes
CPPUNIT_TEST_SUITE_REGISTRATION(PKCS12ParserTest);

void PKCS12ParserTest::teste_construtor_basico() {
    PKCS12Parser parser;
    parser.set_pkcs12_file_path(PKCS12_FILE_PATH);

    // Por segurança, a senha não deve ser armazenada em código, então ela é obtida cifrada com
    // algoritmo AES-256-CBC em base 64 através de uma variável de ambiente.
    parser.set_password(OpenSSLUtils::decrypt_aes_256_cbc(std::getenv(PKCS12_ENVVAR_PASSWORD),
            AES_KEY, reinterpret_cast<const unsigned char*>(AES_INITIALIZATION_VECTOR)));

    // Faz o parse do PKCS12
    std::unique_ptr<Data::POCO::PKCS12POCO> pkcs12_poco = parser.parse();
    CPPUNIT_ASSERT_MESSAGE("Erro de parse causou certificado nulo", pkcs12_poco->certificate.get() != nullptr);
    CPPUNIT_ASSERT_MESSAGE("Erro de parse causou chave privada nula", pkcs12_poco->private_key.get() != nullptr);
}

void PKCS12ParserTest::teste_construtor_sem_senha() {
    PKCS12Parser parser(PKCS12_FILE_PATH);

    // Por segurança, a senha não deve ser armazenada em código, então ela é obtida cifrada com
    // algoritmo AES-256-CBC em base 64 através de uma variável de ambiente.
    parser.set_password(OpenSSLUtils::decrypt_aes_256_cbc(std::getenv(PKCS12_ENVVAR_PASSWORD),
            AES_KEY, reinterpret_cast<const unsigned char*>(AES_INITIALIZATION_VECTOR)));

    // Faz o parse do PKCS12
    std::unique_ptr<Data::POCO::PKCS12POCO> pkcs12_poco = parser.parse();
    CPPUNIT_ASSERT_MESSAGE("Erro de parse causou certificado nulo", pkcs12_poco->certificate.get() != nullptr);
    CPPUNIT_ASSERT_MESSAGE("Erro de parse causou chave privada nula", pkcs12_poco->private_key.get() != nullptr);
}

void PKCS12ParserTest::teste_construtor_com_senha() {
    // Por segurança, a senha não deve ser armazenada em código, então ela é obtida cifrada com
    // algoritmo AES-256-CBC em base 64 através de uma variável de ambiente.
    PKCS12Parser parser(PKCS12_FILE_PATH, OpenSSLUtils::decrypt_aes_256_cbc(std::getenv(PKCS12_ENVVAR_PASSWORD),
            AES_KEY, reinterpret_cast<const unsigned char*>(AES_INITIALIZATION_VECTOR)));

    // Faz o parse do PKCS12
    std::unique_ptr<Data::POCO::PKCS12POCO> pkcs12_poco = parser.parse();
    CPPUNIT_ASSERT_MESSAGE("Erro de parse causou certificado nulo", pkcs12_poco->certificate.get() != nullptr);
    CPPUNIT_ASSERT_MESSAGE("Erro de parse causou chave privada nula", pkcs12_poco->private_key.get() != nullptr);
}

