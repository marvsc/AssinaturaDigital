
#include "../include/CMSSignerTest.h"

#include "CMSSigner.h"
#include "OpenSSLUtils.h"

#include "../include/AssinaturaDigitalMacros.h"

#include <filesystem>

#include <Poco/Crypto/PKCS12Container.h>

// Registra o suite de testes
CPPUNIT_TEST_SUITE_REGISTRATION(CMSSignerTest);

void CMSSignerTest::teste_assinatura_cms_attached_disco_pkcs12_com_senha() {
    // Decripta a senha obtida em uma variável de ambiente
    CMSSigner signer(FILE_TO_ASSIGN_PATH, PKCS12_FILE_PATH, OpenSSLUtils::decrypt_aes_256_cbc(std::getenv(PKCS12_ENVVAR_PASSWORD),
            AES_KEY, reinterpret_cast<const unsigned char*>(AES_INITIALIZATION_VECTOR)));

    // Assina o arquivo
    signer.assign(SIGNATURE_FILE_PATH);

    // Verifica se o arquivo de assinatura foi gerado em disco
    CPPUNIT_ASSERT_MESSAGE(CPPUNIT_PRINTF_MESSAGE("O arquivo %s deveria existir.", SIGNATURE_FILE_PATH),
            std::filesystem::exists(SIGNATURE_FILE_PATH));
}

void CMSSignerTest::teste_assinatura_cms_attached_memoria_pkcs12_com_senha() {
    // Decripta a senha obtida em uma variável de ambiente
    CMSSigner signer(FILE_TO_ASSIGN_PATH, PKCS12_FILE_PATH, OpenSSLUtils::decrypt_aes_256_cbc(std::getenv(PKCS12_ENVVAR_PASSWORD),
            AES_KEY, reinterpret_cast<const unsigned char*>(AES_INITIALIZATION_VECTOR)));

    // Assina o arquivo
    CPPUNIT_ASSERT_MESSAGE("Assinatura em base 64 não foi gerada", !signer.assign().empty());
}

void CMSSignerTest::teste_assinatura_cms_attached_buffer_pkcs12_com_senha() {
    // Decripta a senha obtida em uma variável de ambiente
    CMSSigner signer(FILE_TO_ASSIGN_PATH, PKCS12_FILE_PATH,
            OpenSSLUtils::decrypt_aes_256_cbc(std::getenv(PKCS12_ENVVAR_PASSWORD), AES_KEY,
                    reinterpret_cast<const unsigned char*>(AES_INITIALIZATION_VECTOR)));

    // Instancia um buffer em memória com um buffer em base 64
    std::unique_ptr<BIO, decltype(&BIO_free_all)> memory_buffer(BIO_push(BIO_new(BIO_f_base64()),
            BIO_new(BIO_s_mem())), BIO_free_all);

    // Seta flag para base 64 no buffer
    BIO_set_flags(memory_buffer.get(), BIO_FLAGS_BASE64_NO_NL);

    // Gera a assinatura digital no buffer
    signer.assign(memory_buffer.get());
    BUF_MEM* buffer_pointer = nullptr;

    // Pega o ponteiro para o buffer
    BIO_get_mem_ptr(memory_buffer.get(), &buffer_pointer);
    CPPUNIT_ASSERT_MESSAGE("Não foi possível gerar a assinatura digital no buffer",
            buffer_pointer && buffer_pointer->length > 0 && buffer_pointer->data);
}

void CMSSignerTest::teste_assinatura_cms_attached_pkcs12_inexistente() {
    std::unique_ptr<CMSSigner> signer;

    // Passa um path inexistente para o arquivo PKCS 12 e espera que seja lançada uma exceção
    CPPUNIT_ASSERT_THROW_MESSAGE("Deveria ter lançado exceção de arquivo PKCS 12 inexistente",
            signer.reset(new CMSSigner(FILE_TO_ASSIGN_PATH, PKCS12_FILE_INEXISTENTE_PATH)),
            Poco::OpenFileException);
}

void CMSSignerTest::teste_assinatura_cms_attached_senha_invalida() {
    std::unique_ptr<CMSSigner> signer;

    // Passa uma senha inválida para o arquivo PKCS 12 e espera que seja lançada uma exceção
    CPPUNIT_ASSERT_THROW_MESSAGE("Deveria ter lançado exceção de senha inválida",
            signer.reset(new CMSSigner(FILE_TO_ASSIGN_PATH, PKCS12_FILE_PATH, "senha_invalida")),
            Poco::Crypto::CryptoException);
}

void CMSSignerTest::teste_assinatura_cms_attached_path_inexistente() {
    // Decripta a senha obtida em uma variável de ambiente
    CMSSigner signer(FILE_TO_ASSIGN_PATH, PKCS12_FILE_PATH, OpenSSLUtils::decrypt_aes_256_cbc(std::getenv(PKCS12_ENVVAR_PASSWORD),
            AES_KEY, reinterpret_cast<const unsigned char*>(AES_INITIALIZATION_VECTOR)));

    CPPUNIT_ASSERT_THROW_MESSAGE("Deveria ter lançado exceção de path inexistente",
            signer.assign("path_inexistente/signature.p7s"), std::runtime_error);
}

void CMSSignerTest::teste_assinatura_cms_attached_path_inacessivel() {
    // Decripta a senha obtida em uma variável de ambiente
    CMSSigner signer(FILE_TO_ASSIGN_PATH, PKCS12_FILE_PATH, OpenSSLUtils::decrypt_aes_256_cbc(std::getenv(PKCS12_ENVVAR_PASSWORD),
            AES_KEY, reinterpret_cast<const unsigned char*>(AES_INITIALIZATION_VECTOR)));

    CPPUNIT_ASSERT_THROW_MESSAGE("Deveria ter lançado exceção de path inacessível",
            signer.assign("/root/signature.p7s"), std::runtime_error);
}