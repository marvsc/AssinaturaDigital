
#include "../include/OpenSSLUtils.h"

#include <string>
#include <memory>

#include <openssl/err.h>
#include <openssl/cms.h>
#include <Poco/URIStreamOpener.h>
#include <Poco/URI.h>

#include <Poco/Net/HTTPStreamFactory.h>

/*
 * @brief Função estática com escopo de arquivo para ser usada como callback de erros
 *          do openssl.
 *
 * @param[in] str Ponteiro com a mensagem de erro do openssl.
 * @param[in] len Tamanho da mensagem de erro passada pelo openssl.
 * @param[out] u Ponteiro com o prefixo da mensagem de erro para que a mensagem passada
 *                  pelo openssl seja concatenada a ela.
 *
 * @return 0 para o processamento de erro, 1 continua processando erros da openssl.
 */
static int openssl_error_callback(const char* str, std::size_t len, void* u) {
    std::string* buffer = static_cast<std::string*>(u);

    // Cada erro entre colchetes e separados por vírgula
    buffer->append(buffer->back() == ']' ? ", [" : ": [").append(str).append("]");
    return 1;
}

void OpenSSLUtils::openssl_error_handling(const char* prefix) {
    std::string error_buffer(prefix);
    ERR_print_errors_cb(openssl_error_callback, (void*) &error_buffer);
    throw std::runtime_error(error_buffer.c_str());
}

std::string OpenSSLUtils::base64_decode(const std::string& input) {
    // Instancia um buffer de base 64 e seta flag para não haver quebra de linha
    // XXX: Esse buffer é instanciado sem smart pointer e sem deleter porque será
    //      adicionado a uma cadeia de buffers.
    BIO* base64_buffer = BIO_new(BIO_f_base64());
    BIO_set_flags(base64_buffer, BIO_FLAGS_BASE64_NO_NL);

    // Instancia uma cadeia de buffers com o buffer de base 64 e o buffer da string codificada.
    std::unique_ptr<BIO, decltype(&BIO_free_all)> input_buffer(BIO_push(base64_buffer,
            BIO_new_mem_buf(reinterpret_cast<const unsigned char*>(input.c_str()), input.length())), BIO_free_all);

    // Calcula o tamanho aproximado da string decodificada que deve ser 3/4 +1 do tamanho
    // da string codificada.
    std::size_t output_buffer_length = ((input.length() * 3) / 4) + 1;
    unsigned char* output_buffer = new unsigned char[output_buffer_length];
    if (!output_buffer) {
        throw std::runtime_error("Erro alocando buffer");
    }

    // Decodifica a string em base 64.
    std::size_t output_length = BIO_read(input_buffer.get(), output_buffer, output_buffer_length);
    if (output_length < 0) {
        delete output_buffer;
        output_buffer = nullptr;
        openssl_error_handling("Erro decodificando base 64: ");
    }
    std::string output(reinterpret_cast<const char*>(output_buffer), output_length);
    return output;
}

std::string OpenSSLUtils::decrypt_aes_256_cbc(const std::string& cipher_text, const std::string& key, const unsigned char* initialization_vector) {
    std::string binary = base64_decode(cipher_text);

    // Instancia o contexto de cifra definindo o deleter
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context.get()) {
        openssl_error_handling("Não foi possível criar contexto para decifrar AES: ");
    }

    // Inicializa a decodificação validando chave e vetor de inicialização
    if (!EVP_DecryptInit_ex(context.get(), EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), initialization_vector)){
        openssl_error_handling("Não foi possível inicializar o processo de decifragem AES: ");
    }

    // Declara o buffer da string decifrada calculando o tamanho aproximado
    unsigned char buffer[binary.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc())];
    int buffer_length;

    // Atualiza a decodificação já definido parte do buffer da string decifrada
    if (!EVP_DecryptUpdate(context.get(), buffer, &buffer_length, reinterpret_cast<const unsigned char*>(binary.c_str()), binary.size())) {
        openssl_error_handling("Não foi possível atualizar o processo de decifragem AES: ");
    }

    // Finaliza a decodificação
    if (!EVP_DecryptFinal_ex(context.get(), buffer + buffer_length, &buffer_length)) {
        openssl_error_handling("Não foi possível finalizar o processo de decifragem AES: ");
    }
    std::string plain_text(reinterpret_cast<const char*>(buffer), buffer_length);
    return plain_text;
}

Poco::Crypto::X509Certificate::List OpenSSLUtils::get_ca_cert_chain(const X509* certificate) {
    // Obtém a url do certificado da autoridade certificadora.
    std::string url_cacert(get_issuer_uri(certificate));

    // Baixa o certificado da autoridade certificadora em formato binário (DER).
    std::vector<char> cacert = download_cacert(url_cacert);

    // Converte o DER para estrutura PKCS 7.
    std::unique_ptr<PKCS7, decltype(&PKCS7_free)> pkcs7(pkcs7_buffert_to_structure(cacert), PKCS7_free);

    // Obtém a cadeia de certificados presente no PKCS 7.
    STACK_OF(X509)* certificate_chain = pkcs7->d.sign->cert;

    // Obtém a quantidade de certificados presentes na cadeia de certificados.
    int certificate_chain_size = sk_X509_num(certificate_chain);
    Poco::Crypto::X509Certificate::List cacert_chain;

    // Busca certificados da autoridade certificadora dentro da cadeia de certificados.
    for (int i = 0; i < certificate_chain_size; i++) {

        // Obtém o certificado.
        Poco::Crypto::X509Certificate certificate(sk_X509_value(certificate_chain, i));
        int crit = -1;

        // Obtém as restrições básicas contidas na extenção do certificado.
        std::unique_ptr<BASIC_CONSTRAINTS, decltype(&BASIC_CONSTRAINTS_free)> basic_constraints((BASIC_CONSTRAINTS*) X509_get_ext_d2i(certificate.certificate(),
                NID_basic_constraints, &crit, nullptr), BASIC_CONSTRAINTS_free);

        // Se não houver restrições básicas ou não indicar autoridade certificadora nas restrições
        // básicas, não é certificado da autoridade certificadora.
        if (!basic_constraints.get() || !basic_constraints->ca) {
            continue;
        }

        // Adiciona o certificado da autoridade certificadora a cadeia de certificados.
        cacert_chain.push_back(certificate);
    }
    return cacert_chain;
}

const std::string OpenSSLUtils::get_issuer_uri(const X509* certificate) {
    // Acessa a extenção do certificado.
    X509_EXTENSION *extension = X509_get_ext(certificate, X509_get_ext_by_NID(certificate,
            NID_info_access, -1));
    if (!extension) {
        throw std::runtime_error("Não foi possível extrair a extensão do certificado X509");
    }

    // Extrai as informações de acesso a autoridade certificadora a partir da extenção do
    // certificado.
    std::unique_ptr<AUTHORITY_INFO_ACCESS, decltype(&AUTHORITY_INFO_ACCESS_free)> aia(
            (AUTHORITY_INFO_ACCESS*) X509V3_EXT_d2i(extension), AUTHORITY_INFO_ACCESS_free);
    if (!aia.get()) {
        throw std::runtime_error("Não foi possível decodificar a extensão do certificado X509");
    }

    // Obtém a quantidade de descrição de acessos presente nas informações de acesso a autoridade
    // certificadora.
    int num_aia = sk_ACCESS_DESCRIPTION_num(aia.get());

    // Busca pela url do certificado da autoridade certificadora entre as descrições de acesso.
    for (int i = 0; i < num_aia; i++) {

        // Obtém a descrição do acesso.
        ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(aia.get(), i);

        // Se o identificador numérido não corresponder ao identificador de emissor de autoridade
        // certificadora ou o tipo de localização não corresponder a url geral, a descrição de acesso
        // não corresponde a url.
        if (OBJ_obj2nid(ad->method) != NID_ad_ca_issuers || ad->location->type != GEN_URI) {
            continue;
        }

        // Obtém a url em formato ASN1
        const ASN1_IA5STRING *uri_str = ad->location->d.uniformResourceIdentifier;

        // Verifica se a url encontrada é válida.
        if (uri_str && ASN1_STRING_length(uri_str) <= 0) {
            throw std::runtime_error("URI issuer vazio");
        }

        // Obtém a url convertendo para formato string.
        return reinterpret_cast<const char*>(ASN1_STRING_get0_data(uri_str));
    }

    // Se não encontrar a url, dispara uma exceção.
    throw std::runtime_error("URI issuer não encontrado");
}

const std::vector<char> OpenSSLUtils::download_cacert(const std::string& url) {
    // Registra a fabrica de stream HTTP.
    Poco::Net::HTTPStreamFactory::registerFactory();

    // Define a url para baixar o certificado da autoridade certificadora.
    Poco::URI uri(url);

    // Abre o stream com o certificado da autoridade certificadora.
    std::unique_ptr<std::istream> cacert_stream(Poco::URIStreamOpener::defaultOpener().open(uri));

    // Baixa o certificado da autoridade certificadora para um vetor em memória.
    std::vector<char> cacert_vector(std::istreambuf_iterator<char>(*cacert_stream.get()),
            std::istreambuf_iterator<char>());
    return cacert_vector;
}

PKCS7* OpenSSLUtils::pkcs7_buffert_to_structure(const std::vector<char>& buffer) {
    // Carrega o vetor para um buffer.
    std::unique_ptr<BIO, decltype(&BIO_free)> input(BIO_new_mem_buf(buffer.data(), buffer.size()), BIO_free);

    // Obtém a estrutura PKCS 7 a partir do buffer.
    std::unique_ptr<PKCS7, decltype(&PKCS7_free)> pkcs7(d2i_PKCS7_bio(input.get(), nullptr), PKCS7_free);
    if (!pkcs7.get()) {
        OpenSSLUtils::openssl_error_handling("Erro decodificando PKCS7");
    }

    // Verifica se o PKCS 7 é assinado.
    if (!PKCS7_type_is_signed(pkcs7.get())) {
        throw std::runtime_error("PKCS7 não assinado");
    }

    // Libera o ponteiro para não destruir ao perder o escopo - Não será mais o dono.
    return pkcs7.release();
}
