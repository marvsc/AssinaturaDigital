/*
 * OpenSSLUtilsTest.h
 *
 *  Created on: 2 de abr. de 2026
 *      Author: marcus.chaves
 */

#ifndef TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_OPENSSLUTILSTEST_H_
#define TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_OPENSSLUTILSTEST_H_

#include <cppunit/TestFixture.h>

#include <cppunit/extensions/HelperMacros.h>

class OpenSSLUtilsTest: public CppUnit::TestFixture {
    CPPUNIT_TEST_SUITE(OpenSSLUtilsTest);
    CPPUNIT_TEST(teste_decrypt_aes_256_cbc);
    CPPUNIT_TEST(teste_obter_ca_chain_a_partir_do_certificado);
    CPPUNIT_TEST_SUITE_END();
public:
    void teste_decrypt_aes_256_cbc();
    void teste_obter_ca_chain_a_partir_do_certificado();
};

#endif /* TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_OPENSSLUTILSTEST_H_ */
