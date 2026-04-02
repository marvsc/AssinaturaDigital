/*
 * @file OpenSSLUtils.h
 * @brief Declaração da classe OpenSSLUtils e métodos.
 * @author Marcus Chaves
 * @date 2026-01-27
 */

#ifndef INCLUDE_OPENSSLUTILS_H_
#define INCLUDE_OPENSSLUTILS_H_

#include <stdexcept>

#include <openssl/pkcs7.h>

#include <Poco/Crypto/X509Certificate.h>

/*
 * @class OpenSSLUtils
 * @brief Utilidades para o OpenSSL.
 */
class OpenSSLUtils {
public:
    /*
     * @brief Obtém a descrição completa dos erros gerados pelas
     *          operações do openssl e disparar uma exceção.
     *
     * @param[in] prefix Prefixo da mensagem de erro que será disparada na exceção.
     */
    static void openssl_error_handling(const char* prefix);

    /*
     * @brief Decifra string em base 64 criptografada com algoritmo AES utilizando chave de 256
     *          bits no modo Cipher Block Chaining.
     *
     * @param[in] cipher_text String a ser decifrada.
     * @param[in] key Chave simétrica.
     * @param[in] initialization_vector Vetor de inicialização.
     *
     * @return String decifrada.
     */
    static std::string decrypt_aes_256_cbc(const std::string& cipher_text,
            const std::string& key, const unsigned char* initialization_vector);

    /*
     * @brief Decodifica string em base 64.
     *
     * @param[in] input String em base 64.
     *
     * @return String decodificada.
     */
    static std::string base64_decode(const std::string& input);

    /*
     * @brief Obtém a cadeia de certificados da autoridade certificadora que gerou o certificado.
     *
     * @param[in] certificate Certificado emitido.
     *
     * @return Cadeia de certificados da autoridade certificadora emissora do certificado.
     */
    static Poco::Crypto::X509Certificate::List get_ca_cert_chain(const X509* certificate);
private:
    /*
     * @brief Obtém o url do certificado da autoridade certificadora.
     *
     * @param[in] certificate Certificado gerado pela autoridade certificadora.
     *
     * @return Url para download do certificado a autoridade certificadora.
     */
    static const std::string get_issuer_uri(const X509* certificate);

    /*
     * @brief Efetua download do certificado da autoridade certificadora e mantém em memória.
     *
     * @param[in] url Url para download do certificado da autoridade certificadora.
     *
     * @return Buffer com o certificado da autoridade certificadora.
     */
    static const std::vector<char> download_cacert(const std::string& url);

    /*
     * @brief Obtém a estrutura PKCS 7 a partir de um buffer.
     *
     * @param[in] buffer PKCS 7 em um buffer.
     *
     * @return Estrutura PKCS 7.
     */
    static PKCS7* pkcs7_buffert_to_structure(const std::vector<char>& buffer);
};

#endif /* INCLUDE_OPENSSLUTILS_H_ */
