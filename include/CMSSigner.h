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
    CMSSigner(const std::string &file_to_assign, std::shared_ptr<X509> certificate,
            std::shared_ptr<EVP_PKEY> private_key);
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
