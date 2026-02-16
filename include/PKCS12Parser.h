/*
 * @file PKCS12Parser.h
 * @brief Declaração da classe PKCS12Parser, métodos e atributos.
 * @author Marcus Chaves
 * @date 2026-01-27
 */

#ifndef INCLUDE_PKCS12PARSER_H_
#define INCLUDE_PKCS12PARSER_H_

#include "Data/POCO/PKCS12POCO.h"

#include <memory>
#include <string>

#include <openssl/ssl.h>

/*
 * @class PKCS12Parser
 * @brief Decodificador de arquivos PKCS 12.
 *
 * Extrai chave privada e certificado de arquivo PKCS 12 com ou sem senha.
 */
class PKCS12Parser {
public:

    /*
     * @brief Constrói a classe de forma básica.
     */
    PKCS12Parser() : pkcs12_file_path_(""), password_("") {}

    /*
     * @brief Constrói a classe a partir de um path para um arquivo em formato PKCS 12.
     *
     * @param[in] pkcs12_file_path Path completo para o arquivo no formato PKCS 12.
     */
    PKCS12Parser(const std::string &pkcs12_file_path) : pkcs12_file_path_(pkcs12_file_path), password_("") {}

    /*
     * @brief Constrói a classe a partir de um path para um arquivo em formato PKCS 12 e uma senha.
     *
     * @param[in] pkcs12_file_path Path completo para o arquivo no formato PKCS 12.
     * @param[in] password Senha para acesso ao conteúdo do arquivo PKCS 12.
     */
    PKCS12Parser(const std::string &pkcs12_file_path,
            const std::string &password) : pkcs12_file_path_(pkcs12_file_path), password_(password) {}

    /*
     * @brief Destrói a classe.
     */
    virtual ~PKCS12Parser() {}

    /*
     * @brief Define o path para o arquivo em formato PKCS 12.
     *
     * @param[in] pkcs12_file_path Path completo para o arquivo no formato PKCS 12.
     */
    void set_pkcs12_file_path(const std::string &pkcs12_file_path) {
        pkcs12_file_path_ = pkcs12_file_path;
    }

    /*
     * @brief Define a senha para acesso ao conteúdo do arquivo PKCS 12.
     *
     * @param[in] password Senha para acesso ao conteúdo do arquivo PKCS 12.
     */
    void set_password(const std::string &password) {
        password_ = password;
    }

    /*
     * @brief Extrai o certificado e a chave primária do arquivo PKCS 12, retornando
     *          um poco com o certificado e a chave primária.
     *
     * @return Objeto poco com a chave primária e o certificado.
     */
    Data::POCO::PKCS12POCO parse() const;
private:
    std::string pkcs12_file_path_; ///< @brief Path completo para o arquivo PKCS 12.
    std::string password_; ///< @brief Senha para acesso ao conteúdo do arquivo PKCS 12.

    /*
     * @brief Método privado para obter a descrição completa dos erros gerados pelas
     *          pelas operações do openssl e disparar uma exceção.
     *
     * @param[in] prefix Prefixo da mensagem de erro que será disparada na exceção.
     */
    void openssl_error_handling(const char* prefix) const;
};

#endif /* INCLUDE_PKCS12PARSER_H_ */
