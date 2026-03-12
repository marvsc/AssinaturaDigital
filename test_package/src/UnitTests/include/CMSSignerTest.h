/*
 * @file CMSSignerTest.h
 * @brief Declaração da classe CMSSignerTest
 * @author Marcus Chaves
 */

#ifndef TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_CMSSIGNERTEST_H_
#define TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_CMSSIGNERTEST_H_

#include "PKCS12Parser.h"

#include "Data/POCO/PKCS12POCO.h"

#include <memory>

#include <cppunit/TestFixture.h>

#include <cppunit/extensions/HelperMacros.h>

/*
 * @class CMSSignerTest
 * @brief Classe de testes unitários para o CMSSigner
 */
class CMSSignerTest : public CppUnit::TestFixture {
    // Declaração do suite de testes
    CPPUNIT_TEST_SUITE(CMSSignerTest);
    // Adicionando steps
    CPPUNIT_TEST(teste_construtor_basico_arquivo_assinatura);
    CPPUNIT_TEST(teste_construtor_completo_arquivo_assinatura);
    CPPUNIT_TEST(teste_construtor_basico_base64);
    CPPUNIT_TEST(teste_construtor_completo_base64);
    CPPUNIT_TEST_SUITE_END();

public:

    /*
     * @brief Método para configurar o suite de testes
     */
    void setUp() override;

    /*
     * @brief Método para liberar os recursos do suite de testes
     */
    void tearDown() override;

    /*
     * @brief Teste instanciando o CMSSigner com construtor sem
     *          parâmetros e gerando arquivo de assinatura em
     *          em disco.
     */
    void teste_construtor_basico_arquivo_assinatura();

    /*
     * @brief Teste instanciando o CMSSigner passando path para
     *          o arquivo a ser assinado, certificado e chave
     *          privada para o construtor e gerando arquivo de
     *          assinatura em disco.
     */
    void teste_construtor_completo_arquivo_assinatura();

    /*
     * @brief Teste instanciando o CMSSigner com construtor sem
     *          parâmetros retornando assinatura em base 64 na
     *          memória.
     */
    void teste_construtor_basico_base64();

    /*
     * @brief Teste instanciando o CMSSigner passando path para
     *          o arquivo a ser assinado, certificado e chave
     *          privada para o construtor retornando assinatura
     *          em base 64 na memória.
     */
    void teste_construtor_completo_base64();
private:
    std::unique_ptr<Data::POCO::PKCS12POCO> pkcs12_poco_; ///< @brief Poco contendo certificado e chave priváda
};

#endif /* TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_CMSSIGNERTEST_H_ */
