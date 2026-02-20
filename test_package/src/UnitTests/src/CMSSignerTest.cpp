/*
 * CMSSignerTest.cpp
 *
 *  Created on: 20 de fev. de 2026
 *      Author: marcus.chaves
 */

#include "../include/CMSSignerTest.h"

#include "CMSSigner.h"

#include "../include/AssinaturaDigitalMacros.h"
#include "Data/POCO/PKCS12POCO.h"

#include <filesystem>

CPPUNIT_TEST_SUITE_REGISTRATION(CMSSignerTest);

void CMSSignerTest::setUp() {
    PKCS12Parser parser(PKCS12_FILE_PATH, PKCS12_PASSWORD);
    pkcs12_poco_ = std::make_unique<Data::POCO::PKCS12POCO>(parser.parse());
}

void CMSSignerTest::tearDown() {
    pkcs12_poco_.reset();
}

void CMSSignerTest::teste_construtor_basico_arquivo_assinatura() {
    CMSSigner signer;
    signer.set_certificate(pkcs12_poco_->certificate);
    signer.set_private_key(pkcs12_poco_->private_key);
    signer.set_file_to_assign(FILE_TO_ASSIGN_PATH);
    signer.assign(SIGNATURE_FILE_PATH);
    std::string message("O arquivo ");
    CPPUNIT_ASSERT_MESSAGE(message.append(SIGNATURE_FILE_PATH).append(" deveria existir").c_str(),
            std::filesystem::exists(SIGNATURE_FILE_PATH));
}

void CMSSignerTest::teste_construtor_basico_base64() {
    CMSSigner signer;
    signer.set_certificate(pkcs12_poco_->certificate);
    signer.set_private_key(pkcs12_poco_->private_key);
    signer.set_file_to_assign(FILE_TO_ASSIGN_PATH);
    std::string assinatura_base64(signer.assign());
    CPPUNIT_ASSERT_MESSAGE("Assinatura em branco", !assinatura_base64.empty());
}

void CMSSignerTest::teste_construtor_completo_arquivo_assinatura() {
    CMSSigner signer(FILE_TO_ASSIGN_PATH, pkcs12_poco_->certificate, pkcs12_poco_->private_key);
    signer.assign(SIGNATURE_FILE_PATH);
    std::string message("O arquivo ");
    CPPUNIT_ASSERT_MESSAGE(message.append(SIGNATURE_FILE_PATH).append(" deveria existir").c_str(),
            std::filesystem::exists(SIGNATURE_FILE_PATH));
}

void CMSSignerTest::teste_construtor_completo_base64() {
    CMSSigner signer(FILE_TO_ASSIGN_PATH, pkcs12_poco_->certificate, pkcs12_poco_->private_key);
    std::string assinatura_base64(signer.assign());
    CPPUNIT_ASSERT_MESSAGE("Assinatura em branco", !assinatura_base64.empty());
}
