/*
 * CMSSigner.h
 *
 *  Created on: 13/06/2025
 *      Author: marcus
 */

#ifndef INCLUDE_CMSSIGNER_H_
#define INCLUDE_CMSSIGNER_H_

#include <memory>
#include <string>

#include <openssl/ssl.h>

class CMSSigner {
public:
    CMSSigner();
    CMSSigner(const std::string &file_to_assign, X509 *const certificate,
            EVP_PKEY *const private_key);
    virtual ~CMSSigner() {
    }
    void set_file_to_assign(const std::string &file_to_assign) {
        file_to_assign_ = file_to_assign;
    }
    void set_certificate(X509 *const certificate) {
        certificate_.reset(certificate);
    }
    void set_private_key(EVP_PKEY *const private_key) {
        private_key_.reset(private_key);
    }
    void assign(const std::string &signature_file) const;
private:
    std::string file_to_assign_;
    std::unique_ptr<X509, void(*)(X509*)> certificate_;
    std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> private_key_;
};

#endif /* INCLUDE_CMSSIGNER_H_ */
