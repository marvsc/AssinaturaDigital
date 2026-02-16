/*
 * @file PKCS12POCO.h
 * @brief Declaração do Plain Old C++ Object PKCS12POCO e atributos.
 * @author Marcus Chaves
 * @date 2026-01-27
 */

#ifndef INCLUDE_DATA_POCO_PKCS12POCO_H_
#define INCLUDE_DATA_POCO_PKCS12POCO_H_

#include <memory>

#include <openssl/ssl.h>

namespace Data {
namespace POCO {

/*
 * @class PKCS12POCO
 * @brief POCO para armazenar as informações sobre certificado e chave primária contidas no arquivo PKCS 12.
 */
class PKCS12POCO {
public:
    std::shared_ptr<X509> certificate; ///< @brief Certificado X509
    std::shared_ptr<EVP_PKEY> private_key; ///< @brief Chave primária

    /*
     * @brief Constrói o POCO com base em um certificado e uma chave primária
     *
     * @param[in] certificate Certificado X509.
     * @param[in] private_key Chave primária.
     */
    PKCS12POCO(std::shared_ptr<X509> certificate, std::shared_ptr<EVP_PKEY> private_key) : certificate(certificate), private_key(private_key) {}

    /*
     * @brief Destrói o POCO.
     */
    virtual ~PKCS12POCO() {
        certificate.reset();
        private_key.reset();
    }
};

} /* namespace POCO */
} /* namespace Data */

#endif /* INCLUDE_DATA_POCO_PKCS12POCO_H_ */
