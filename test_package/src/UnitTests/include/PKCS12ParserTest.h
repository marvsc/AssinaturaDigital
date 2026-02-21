/*
 * @file PKCS12ParserTest.h
 * @brief Declaração da classe PKCS12ParserTest
 * @author Marcus Chaves
 */

#ifndef TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_PKCS12PARSERTEST_H_
#define TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_PKCS12PARSERTEST_H_

#include <cppunit/TestFixture.h>

#include <cppunit/extensions/HelperMacros.h>

/*
 * @class PKCS12ParserTest
 * @brief Classe de testes unitários para o PKCS12Parser
 */
class PKCS12ParserTest : public CppUnit::TestFixture {
    // Declaração do suite de testes
    CPPUNIT_TEST_SUITE(PKCS12ParserTest);
    // Adicinando steps
    CPPUNIT_TEST(teste_construtor_basico);
    CPPUNIT_TEST(teste_construtor_sem_senha);
    CPPUNIT_TEST(teste_construtor_com_senha);
    CPPUNIT_TEST_SUITE_END();

public:

    /*
     * @brief Teste instanciando o PKCS12Parser com construtor sem
     *          parâmetros.
     */
    void teste_construtor_basico();

    /*
     * @brief Teste instanciando o PKCS12Parser somente com o path
     *          para o arquivo no formato PKCS 12.
     */
    void teste_construtor_sem_senha();

    /*
     * @brief Teste instanciando o PKCS12Parser passando o path para
     *          o arquivo no formato PKCS 12 e a senha para acesso aos
     *          dados.
     */
    void teste_construtor_com_senha();
};

#endif /* TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_PKCS12PARSERTEST_H_ */
