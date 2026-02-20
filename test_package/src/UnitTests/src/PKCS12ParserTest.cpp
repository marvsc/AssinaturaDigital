/*
 * PKCS12ParserTest.cpp
 *
 *  Created on: 20 de fev. de 2026
 *      Author: marcus.chaves
 */

#include "../include/PKCS12ParserTest.h"

#include "PKCS12Parser.h"

#include "../include/AssinaturaDigitalMacros.h"

#include "Data/POCO/PKCS12POCO.h"

CPPUNIT_TEST_SUITE_REGISTRATION(PKCS12ParserTest);

void PKCS12ParserTest::teste_construtor_basico() {
    PKCS12Parser parser;
    parser.set_pkcs12_file_path(PKCS12_FILE_PATH);
    parser.set_password(PKCS12_PASSWORD);
    Data::POCO::PKCS12POCO pkcs12_poco = parser.parse();
    CPPUNIT_ASSERT_MESSAGE("Erro de parse causou certificado nulo", pkcs12_poco.certificate.get() != nullptr);
    CPPUNIT_ASSERT_MESSAGE("Erro de parse causou chave privada nula", pkcs12_poco.private_key.get() != nullptr);
}

void PKCS12ParserTest::teste_construtor_sem_senha() {
    PKCS12Parser parser(PKCS12_FILE_PATH);
    parser.set_password(PKCS12_PASSWORD);
    Data::POCO::PKCS12POCO pkcs12_poco = parser.parse();
    CPPUNIT_ASSERT_MESSAGE("Erro de parse causou certificado nulo", pkcs12_poco.certificate.get() != nullptr);
    CPPUNIT_ASSERT_MESSAGE("Erro de parse causou chave privada nula", pkcs12_poco.private_key.get() != nullptr);
}

void PKCS12ParserTest::teste_construtor_com_senha() {
    PKCS12Parser parser(PKCS12_FILE_PATH, PKCS12_PASSWORD);
    Data::POCO::PKCS12POCO pkcs12_poco = parser.parse();
    CPPUNIT_ASSERT_MESSAGE("Erro de parse causou certificado nulo", pkcs12_poco.certificate.get() != nullptr);
    CPPUNIT_ASSERT_MESSAGE("Erro de parse causou chave privada nula", pkcs12_poco.private_key.get() != nullptr);
}

