
#include "../include/CMSSignerTest.h"

#include "CMSSigner.h"
#include "OpenSSLUtils.h"

#include "../include/AssinaturaDigitalMacros.h"
#include "Data/POCO/PKCS12POCO.h"

#include <filesystem>

// Registra o suite de testes
CPPUNIT_TEST_SUITE_REGISTRATION(CMSSignerTest);

void CMSSignerTest::setUp() {
    // Instancia o parser PKCS 12
    PKCS12Parser parser(PKCS12_FILE_PATH, OpenSSLUtils::decrypt_aes_256_cbc(std::getenv(PKCS12_ENVVAR_PASSWORD),
            AES_KEY, reinterpret_cast<const unsigned char*>(AES_INITIALIZATION_VECTOR)));
    pkcs12_poco_ = parser.parse();
}

void CMSSignerTest::tearDown() {
    // Libera a memória utilizada pelo poco PKCS 12 explicitamente.
    pkcs12_poco_.reset();
}

void CMSSignerTest::teste_construtor_basico_arquivo_assinatura() {
    CMSSigner signer;
    signer.set_certificate(pkcs12_poco_->certificate.release());
    signer.set_private_key(pkcs12_poco_->private_key.release());
    signer.set_file_to_assign(FILE_TO_ASSIGN_PATH);

    // Assina o arquivo
    signer.assign(SIGNATURE_FILE_PATH);
    std::string message("O arquivo ");

    // Verifica se o arquivo de assinatura foi gerado em disco
    CPPUNIT_ASSERT_MESSAGE(message.append(SIGNATURE_FILE_PATH).append(" deveria existir").c_str(),
            std::filesystem::exists(SIGNATURE_FILE_PATH));
}

void CMSSignerTest::teste_construtor_basico_base64() {
    CMSSigner signer;
    signer.set_certificate(pkcs12_poco_->certificate.release());
    signer.set_private_key(pkcs12_poco_->private_key.release());
    signer.set_file_to_assign(FILE_TO_ASSIGN_PATH);

    // Assina o arquivo
    std::string assinatura_base64(signer.assign());

    // Verifica se a assinatura foi gerada
    CPPUNIT_ASSERT_MESSAGE("Assinatura em branco", !assinatura_base64.empty());
}

void CMSSignerTest::teste_construtor_completo_arquivo_assinatura() {
    CMSSigner signer(FILE_TO_ASSIGN_PATH, pkcs12_poco_->certificate.release(), pkcs12_poco_->private_key.release());

    // Assina o arquivo
    signer.assign(SIGNATURE_FILE_PATH);
    std::string message("O arquivo ");

    // Verifica se o arquivo de assinatura foi gerado em disco
    CPPUNIT_ASSERT_MESSAGE(message.append(SIGNATURE_FILE_PATH).append(" deveria existir").c_str(),
            std::filesystem::exists(SIGNATURE_FILE_PATH));
}

void CMSSignerTest::teste_construtor_completo_base64() {
    CMSSigner signer(FILE_TO_ASSIGN_PATH, pkcs12_poco_->certificate.release(), pkcs12_poco_->private_key.release());

    // Assina o arquivo
    std::string assinatura_base64(signer.assign());

    // Verifica se a assinatura foi gerada
    CPPUNIT_ASSERT_MESSAGE("Assinatura em branco", !assinatura_base64.empty());
}
