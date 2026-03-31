
#include "../include/CMSSignerTest.h"

#include "CMSSigner.h"
#include "OpenSSLUtils.h"

#include "../include/AssinaturaDigitalMacros.h"

#include <filesystem>

#include <Poco/Crypto/PKCS12Container.h>

// Registra o suite de testes
CPPUNIT_TEST_SUITE_REGISTRATION(CMSSignerTest);

void CMSSignerTest::teste_assinatura_cms_attached_pkcs12_com_senha() {
    // Decripta a senha obtida em uma variável de ambiente
    CMSSigner signer(FILE_TO_ASSIGN_PATH, PKCS12_FILE_PATH, OpenSSLUtils::decrypt_aes_256_cbc(std::getenv(PKCS12_ENVVAR_PASSWORD),
            AES_KEY, reinterpret_cast<const unsigned char*>(AES_INITIALIZATION_VECTOR)));

    // Assina o arquivo
    signer.assign(SIGNATURE_FILE_PATH);
    std::string message("O arquivo ");

    // Verifica se o arquivo de assinatura foi gerado em disco
    CPPUNIT_ASSERT_MESSAGE(message.append(SIGNATURE_FILE_PATH).append(" deveria existir").c_str(),
            std::filesystem::exists(SIGNATURE_FILE_PATH));
}
