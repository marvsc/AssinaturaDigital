/*
 * @file OpenSSLUtilsTest.h
 * @brief Declaração da classe OpenSSLUtilsTest
 * @author Marcus Chaves
 * @date 2026-01-27
 */

#ifndef TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_OPENSSLUTILSTEST_H_
#define TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_OPENSSLUTILSTEST_H_

#include <cppunit/TestFixture.h>

#include <cppunit/extensions/HelperMacros.h>

/*
 * @class CMSSignerTest
 * @brief Classe de testes unitários para o OpenSSLUtils
 */
class OpenSSLUtilsTest: public CppUnit::TestFixture {
    // Declaração do suite de testes
    CPPUNIT_TEST_SUITE(OpenSSLUtilsTest);
    // Adicionando steps
    CPPUNIT_TEST(teste_decrypt_aes_256_cbc);
    CPPUNIT_TEST(teste_obter_ca_chain_a_partir_do_certificado);
    CPPUNIT_TEST(teste_decodificacao_base64);
    CPPUNIT_TEST(teste_obter_url_certificado_autoridade_certificadora);
    CPPUNIT_TEST_SUITE_END();

public:

    /*
     * @brief Teste para decriptar string usando algoritmo AES-256-CBC.
     */
    void teste_decrypt_aes_256_cbc();

    /*
     * @brief Teste para obter a cadeia de certificados da autoridade certificadora
     *          a partir do certificado gerado.
     */
    void teste_obter_ca_chain_a_partir_do_certificado();

    /*
     * @brief Teste de decodificação de string em base 64.
     */
    void teste_decodificacao_base64();

    /*
     * @brief Teste para obter a url do certificado da autoridade certificadora.
     */
    void teste_obter_url_certificado_autoridade_certificadora();
};

#endif /* TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_OPENSSLUTILSTEST_H_ */
