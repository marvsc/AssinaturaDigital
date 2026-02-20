/*
 * PKCS12ParserTest.h
 *
 *  Created on: 20 de fev. de 2026
 *      Author: marcus.chaves
 */

#ifndef TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_PKCS12PARSERTEST_H_
#define TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_PKCS12PARSERTEST_H_

#include <cppunit/TestFixture.h>

#include <cppunit/extensions/HelperMacros.h>

class PKCS12ParserTest : public CppUnit::TestFixture {
    CPPUNIT_TEST_SUITE(PKCS12ParserTest);
    CPPUNIT_TEST(teste_construtor_basico);
    CPPUNIT_TEST(teste_construtor_sem_senha);
    CPPUNIT_TEST(teste_construtor_com_senha);
    CPPUNIT_TEST_SUITE_END();

public:
    void teste_construtor_basico();
    void teste_construtor_sem_senha();
    void teste_construtor_com_senha();
};

#endif /* TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_PKCS12PARSERTEST_H_ */
