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

#include <openssl/ssl.h>

/*
 * @class CMSSigner
 * @brief Classe para assinar arquivos digitalmente utilizando algoritmo CMS attached.
 */
class CMSSigner {
public:

    /*
     * @brief Constrói a classe de forma básica
     */
    CMSSigner();

    /*
     * @brief Constrói a classe a partir de um path para um arquivo a ser assinado,
     *          um certificado e uma chave primária
     *
     * @param[in] file_to_assign Path completo para o arquivo a ser assinado.
     * @param[in] certificate Certificado X509.
     * @param[in] private_key Chave primária.
     */
    CMSSigner(const std::string &file_to_assign, std::shared_ptr<X509> certificate,
            std::shared_ptr<EVP_PKEY> private_key);

    /*
     * @brief Destrói a classe.
     */
    virtual ~CMSSigner() {
    }
    void set_file_to_assign(const std::string &file_to_assign) {
        file_to_assign_ = file_to_assign;
    }
    void set_certificate(std::shared_ptr<X509> certificate) {
        certificate_ = certificate;
    }
    void set_private_key(std::shared_ptr<EVP_PKEY> private_key) {
        private_key_ = private_key;
    }
    void assign(const std::string &signature_file) const;
    std::string assign() const;
private:
    std::string file_to_assign_;
    std::weak_ptr<X509> certificate_;
    std::weak_ptr<EVP_PKEY> private_key_;

    void assign(BIO* buffer) const;
};

#endif /* INCLUDE_CMSSIGNER_H_ */
