
#include "CMSSigner.h"

#include "../include/OpenSSLUtils.h"

#include <stdexcept>

#include <openssl/cms.h>
#include <openssl/err.h>

CMSSigner::CMSSigner(const std::string &file_to_assign, const std::string& pkcs12_path) :
        file_to_assign_(file_to_assign), container_(pkcs12_path) {
}

CMSSigner::CMSSigner(const std::string& file_to_assign, const std::string& pkcs12_path, const std::string& password) :
        file_to_assign_(file_to_assign), container_(pkcs12_path, password) {
}

void CMSSigner::assign(BIO* buffer) const {
    // Cria um buffer para o arquivo em modo leitura já definindo o deleter
    std::unique_ptr<BIO, decltype(&BIO_vfree)> file_buffer(
            BIO_new_file(file_to_assign_.c_str(), "rb"), BIO_vfree);

    // Gera a assinatura para o arquivo já definindo o deleter para a assinatura
    std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)> content_info(
            CMS_sign(const_cast<X509*>(container_.getX509Certificate().certificate()), container_.getKey(),
                    nullptr, file_buffer.get(), CMS_BINARY), CMS_ContentInfo_free);

    // Despeja o conteúda da assinatura no buffer recebido por parâmetro
    if (!i2d_CMS_bio(buffer, content_info.get())) {
        OpenSSLUtils::openssl_error_handling("Erro escrevendo assinatura");
    }
}

void CMSSigner::assign(const std::string &signature_file) const {
    // Abre um buffer para um arquivo de assinatura em modo escrita
    std::unique_ptr<BIO, decltype(&BIO_vfree)> output_buffer(
            BIO_new_file(signature_file.c_str(), "wb"), BIO_vfree);
    assign(output_buffer.get());
}

std::string CMSSigner::assign() const {
    // Integra um buffer em memória com um buffer em base 64
    std::unique_ptr<BIO, decltype(&BIO_free_all)> memory_buffer(BIO_push(BIO_new(BIO_f_base64()), BIO_new(BIO_s_mem())), BIO_free_all);

    // Seta flag para base 64 no buffer
    BIO_set_flags(memory_buffer.get(), BIO_FLAGS_BASE64_NO_NL);
    assign(memory_buffer.get());
    BUF_MEM* buffer_pointer = nullptr;

    // Pega o ponteiro para o buffer
    BIO_get_mem_ptr(memory_buffer.get(), &buffer_pointer);
    if (!buffer_pointer || buffer_pointer->length == 0) {
        return "";
    }

    // Despeja o buffer em uma string
    std::string signature(buffer_pointer->data, buffer_pointer->length);
    return signature;
}
