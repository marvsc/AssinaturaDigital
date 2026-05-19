/*
 * @file CMSSignerTest.h
 * @brief Declaração da classe CMSSignerTest
 * @author Marcus Chaves
 * @date 2026-01-27
 */

#ifndef TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_CMSSIGNERTEST_H_
#define TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_CMSSIGNERTEST_H_

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
    CPPUNIT_TEST(teste_assinatura_cms_attached_disco_pkcs12_com_senha);
    CPPUNIT_TEST(teste_assinatura_cms_attached_memoria_pkcs12_com_senha);
    CPPUNIT_TEST(teste_assinatura_cms_attached_buffer_pkcs12_com_senha);
    CPPUNIT_TEST_SUITE_END();

public:

    /*
     * @brief Teste para gerar assinatura em disco utilizando
     *          algoritmo CMS attached utilizando certificados
     *          encapsulados em formato PKCS 12 com senha.
     */
    void teste_assinatura_cms_attached_disco_pkcs12_com_senha();

    /*
     * @brief Teste para gerar assinatura em memória utilizando
     *          algoritmo CMS attached em base 64 utilizando
     *          certificados encapsulados em formato PKCS 12
     *          com senha.
     */
    void teste_assinatura_cms_attached_memoria_pkcs12_com_senha();

    /*
     * @brief Teste para gerar assinatura em buffer de memória
     *          utilizando algoritmo CMS attached utilizando
     *          certificados encapsulados em formato PKCS 12
     *          com senha.
     */
    void teste_assinatura_cms_attached_buffer_pkcs12_com_senha();
};

#endif /* TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_CMSSIGNERTEST_H_ */
