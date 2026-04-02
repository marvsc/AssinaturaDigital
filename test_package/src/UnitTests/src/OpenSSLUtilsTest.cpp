/*
 * OpenSSLUtilsTest.cpp
 *
 *  Created on: 2 de abr. de 2026
 *      Author: marcus.chaves
 */

#include "../include/OpenSSLUtilsTest.h"

#include "../include/AssinaturaDigitalMacros.h"

#include "OpenSSLUtils.h"

#include <Poco/Crypto/PKCS12Container.h>
#include <Poco/Crypto/X509Certificate.h>

CPPUNIT_TEST_SUITE_REGISTRATION(OpenSSLUtilsTest);

void OpenSSLUtilsTest::teste_decrypt_aes_256_cbc() {
    CPPUNIT_ASSERT_MESSAGE(CPPUNIT_PRINTF_MESSAGE("Não foi possível decriptar o texto %s", std::getenv(PKCS12_ENVVAR_PASSWORD)),
            OpenSSLUtils::decrypt_aes_256_cbc(std::getenv(PKCS12_ENVVAR_PASSWORD), AES_KEY,
                    reinterpret_cast<const unsigned char*>(AES_INITIALIZATION_VECTOR)).size() > 0);
}

void OpenSSLUtilsTest::teste_obter_ca_chain_a_partir_do_certificado() {
    Poco::Crypto::PKCS12Container container(PKCS12_FILE_PATH,
            OpenSSLUtils::decrypt_aes_256_cbc(std::getenv(PKCS12_ENVVAR_PASSWORD), AES_KEY,
                    reinterpret_cast<const unsigned char*>(AES_INITIALIZATION_VECTOR)));
    CPPUNIT_ASSERT_MESSAGE(CPPUNIT_PRINTF_MESSAGE("Não foi possível obter a cadeia de certificados da "
            "autoridade certificadora emissora do certificado %s", PKCS12_FILE_PATH),
            OpenSSLUtils::get_ca_cert_chain(container.getX509Certificate().certificate()).size() > 0);
}
