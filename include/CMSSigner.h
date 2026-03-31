/*
 * @file CMSSigner.h
 * @brief Declaração da classe CMSSigner
 * @author Marcus Chaves
 * @date 2026-01-27
 */

#ifndef INCLUDE_CMSSIGNER_H_
#define INCLUDE_CMSSIGNER_H_

#include <memory>
#include <string>

#include <Poco/Crypto/PKCS12Container.h>

/*
 * @class CMSSigner
 * @brief Classe para assinar arquivos digitalmente utilizando algoritmo CMS attached.
 */
class CMSSigner {
public:

    /*
     * @brief Constrói a classe a partir de um path para um arquivo a ser assinado e
     *          o path para um arquivo PKCS 12.
     *
     * @param[in] file_to_assign Path completo para o arquivo a ser assinado.
     * @param[in] pkcs12_path Path completo para o arquivo PKCS 12.
     */
    CMSSigner(const std::string &file_to_assign, const std::string& pkcs12_path);

    /*
     * @brief Constrói a classe a partir de um path para um arquivo a ser assinado,
     *          o path para um arquivo PKCS 12 e uma senha.
     *
     * @param[in] file_to_assign Path completo para o arquivo a ser assinado.
     * @param[in] pkcs12_path Path completo para arquivo PKCS 12.
     * @param[in] password Senha de acesso aos dados do arquivo PKCS 12.
     */
    CMSSigner(const std::string& file_to_assign, const std::string& pkcs12_path,
            const std::string& password);

    /*
     * @brief Destrói a classe.
     */
    virtual ~CMSSigner() {}

    /*
     * @brief Assina o arquivo definido no atributo file_to_assign_ e gera um aquivo
     *          de assinatura.
     *
     * @param[in] signature_file Path completo onde o arquivo de assinatura deve
     *                              ser gerado.
     */
    void assign(const std::string &signature_file) const;

    /*
     * @brief Assina o arquivo definido no atributo file_to_assign_ e retorna a
     *          assinatura CMS codificada em base 64.
     *
     * @return Assinatura CMS codificada em base 64 do arquivo definido no
     *          atributo file_to_assign_.
     */
    std::string assign() const;
private:
    std::string file_to_assign_; ///< @brief Path completo para o arquivo a ser assinado.
    Poco::Crypto::PKCS12Container container_; ///< @brief container com os certificados.

    /*
     * @brief Método privado para assinar o arquivo definido pelo atributo file_to_assign_
     *          gerando a assinatura no buffer recebido como parâmetro. O buffer pode
     *          vir de um arquivo em disco ou da memória sendo codificado em base 64
     *          ou não.
     *
     * @param[in] buffer Buffer onde será gerada a assinatura CMS.
     */
    void assign(BIO* buffer) const;
};

#endif /* INCLUDE_CMSSIGNER_H_ */
