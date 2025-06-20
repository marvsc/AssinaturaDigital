/*
 * CMSSigner.cpp
 *
 *  Created on: 13/06/2025
 *      Author: marcus
 */

#include "CMSSigner.h"

#include <stdexcept>

#include <openssl/cms.h>
#include <openssl/err.h>

CMSSigner::CMSSigner() :
        file_to_assign_("") {
}

CMSSigner::CMSSigner(const std::string &file_to_assign,
        std::shared_ptr<X509> certificate,
        std::shared_ptr<EVP_PKEY> private_key) :
        file_to_assign_(file_to_assign), certificate_(certificate), private_key_(
                private_key) {
}

void CMSSigner::assign(const std::string &signature_file) const {
    std::unique_ptr<BIO, decltype(&BIO_vfree)> file_buffer(
            BIO_new_file(file_to_assign_.c_str(), "rb"), BIO_vfree);
    std::unique_ptr<BIO, decltype(&BIO_vfree)> output_buffer(
            BIO_new_file(signature_file.c_str(), "wb"), BIO_vfree);
    std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)> content_info(
            CMS_sign(certificate_.lock().get(), private_key_.lock().get(), NULL,
                    file_buffer.get(), CMS_BINARY), CMS_ContentInfo_free);
    if (!i2d_CMS_bio(output_buffer.get(), content_info.get())) {
        ERR_print_errors_cb([](const char* str, std::size_t len, void* u) {
            std::string str_prefix(static_cast<const char*>(u));
            throw std::runtime_error(str_prefix.append(": ").append(str, len));
            return 0;
        }, (void*)"Erro escrevendo assinatura");
    }
}
