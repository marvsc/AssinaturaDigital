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
        file_to_assign_(""), certificate_(nullptr, [](X509 *_certificate) {
            X509_free(_certificate);
            _certificate = nullptr;
        }), private_key_(nullptr, [](EVP_PKEY *_private_key) {
            EVP_PKEY_free(_private_key);
            _private_key = nullptr;
        }) {
}

CMSSigner::CMSSigner(const std::string &file_to_assign, X509 *const certificate,
        EVP_PKEY *const private_key) :
        file_to_assign_(file_to_assign), certificate_(certificate,
                [](X509 *_certificate) {
                    X509_free(_certificate);
                    _certificate = nullptr;
                }), private_key_(private_key, [](EVP_PKEY *_private_key) {
            EVP_PKEY_free(_private_key);
            _private_key = nullptr;
        }) {
}

void CMSSigner::assign(const std::string &signature_file) const {
    auto buffer_deleter = [](BIO* _buffer) {
        BIO_vfree(_buffer);
        _buffer = nullptr;
    };
    std::unique_ptr<BIO, decltype(buffer_deleter)> file_buffer(nullptr, buffer_deleter);
    std::unique_ptr<BIO, decltype(buffer_deleter)> output_buffer(nullptr, buffer_deleter);
    std::unique_ptr<CMS_ContentInfo, void(*)(CMS_ContentInfo*)> content_info(nullptr,
            [](CMS_ContentInfo* _content_info) {
        CMS_ContentInfo_free(_content_info);
        _content_info = nullptr;
    });
    auto clean = [&]() {
        file_buffer.reset();
        output_buffer.reset();
        content_info.reset();
    };
    try {
        file_buffer.reset(BIO_new_file(file_to_assign_.c_str(), "rb"));
        output_buffer.reset(BIO_new_file(signature_file.c_str(), "wb"));
        content_info.reset(
                CMS_sign(certificate_.get(), private_key_.get(), NULL,
                        file_buffer.get(), CMS_BINARY));
        if (!i2d_CMS_bio(output_buffer.get(), content_info.get())) {
            unsigned long error = ERR_get_error();
            throw std::runtime_error(
                    std::string("Erro escrevendo assinatura: [").append(
                            std::to_string(error)).append("] - ").append(
                            ERR_error_string(error, NULL)).c_str());
        }
    } catch (...) {
        clean();
        throw;
    }
    clean();
}
