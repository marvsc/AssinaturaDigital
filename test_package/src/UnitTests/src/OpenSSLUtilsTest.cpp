
#include "../include/OpenSSLUtilsTest.h"

#include "../include/AssinaturaDigitalMacros.h"

#include "OpenSSLUtils.h"

#include <Poco/Crypto/PKCS12Container.h>
#include <Poco/Crypto/X509Certificate.h>

// Registra o suite de testes
CPPUNIT_TEST_SUITE_REGISTRATION(OpenSSLUtilsTest);

void OpenSSLUtilsTest::teste_decrypt_aes_256_cbc() {
    // Decripta a senha obtida em uma variável de ambiente
    CPPUNIT_ASSERT_MESSAGE(CPPUNIT_PRINTF_MESSAGE("Não foi possível decriptar o texto %s", std::getenv(PKCS12_ENVVAR_PASSWORD)),
            OpenSSLUtils::decrypt_aes_256_cbc(std::getenv(PKCS12_ENVVAR_PASSWORD), AES_KEY,
                    reinterpret_cast<const unsigned char*>(AES_INITIALIZATION_VECTOR)).size() > 0);
}

void OpenSSLUtilsTest::teste_obter_ca_chain_a_partir_do_certificado() {
    // Instancia o container PKCS 12
    Poco::Crypto::PKCS12Container container(PKCS12_FILE_PATH,
            OpenSSLUtils::decrypt_aes_256_cbc(std::getenv(PKCS12_ENVVAR_PASSWORD), AES_KEY,
                    reinterpret_cast<const unsigned char*>(AES_INITIALIZATION_VECTOR)));

    // Obtém a cadeia de certificados da autoridade certificadora a partir do certificado obtido no arquivo
    // PKCS 12.
    CPPUNIT_ASSERT_MESSAGE(CPPUNIT_PRINTF_MESSAGE("Não foi possível obter a cadeia de certificados da "
            "autoridade certificadora emissora do certificado %s", PKCS12_FILE_PATH),
            OpenSSLUtils::get_ca_cert_chain(container.getX509Certificate().certificate()).size() > 0);
}

void OpenSSLUtilsTest::teste_decodificacao_base64() {
    // Decodifica Hello World em base64
    CPPUNIT_ASSERT_MESSAGE(CPPUNIT_PRINTF_MESSAGE("String %s não foi decodificada em %s",
            HELLO_WORLD_BASE64, HELLO_WORLD), OpenSSLUtils::base64_decode(HELLO_WORLD_BASE64) == HELLO_WORLD);
}

void OpenSSLUtilsTest::teste_obter_url_certificado_autoridade_certificadora() {
    // Instancia o container PKCS 12
    Poco::Crypto::PKCS12Container container(PKCS12_FILE_PATH,
            OpenSSLUtils::decrypt_aes_256_cbc(std::getenv(PKCS12_ENVVAR_PASSWORD), AES_KEY,
                    reinterpret_cast<const unsigned char*>(AES_INITIALIZATION_VECTOR)));
    std::unique_ptr<X509, decltype(&X509_free)> certificate(container.getX509Certificate().dup(), X509_free);

    // Obtém a url do certificado da autoridade certificadora.
    std::string issuer_uri(OpenSSLUtils::get_issuer_uri(certificate.get()));
    CPPUNIT_ASSERT_MESSAGE(CPPUNIT_PRINTF_MESSAGE("URL %s obtida no certificado não corresponde URL %s definida como URL do certificado da autoridade certificadora",
            issuer_uri.c_str(), ISSUER_URI), issuer_uri == ISSUER_URI);
}

