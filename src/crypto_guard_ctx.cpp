#include "crypto_guard_ctx.h"
#include <array>
#include <fstream>
#include <openssl/evp.h>
#include <stdexcept>
#include <vector>
namespace CryptoGuard {
struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};
class CryptoGuardCtx::PImpl {
public:
    PImpl() { OpenSSL_add_all_algorithms(); }
    ~PImpl() { EVP_cleanup(); }
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::iostream &inStream);

private:
    void CheckStreams(std::iostream &inStream, std::iostream &outStream);

    void ProcessCommand(std::iostream &inStream, std::iostream &outStream, std::string_view password,
                        EVP_CIPHER_CTX *ctx);
    AesCipherParams CreateChiperParamsFromPassword(std::string_view password);
};

using UniqueEVPCtx = std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })>;

void CryptoGuardCtx::PImpl::CheckStreams(std::iostream &inStream, std::iostream &outStream) {
    if (!inStream.good() || !outStream.good()) {
        throw std::runtime_error("Stream is in bad state");
    }
    inStream.peek();
    if (inStream.eof()) {
        throw std::runtime_error("Input stream is empty");
    }
}
void CryptoGuardCtx::PImpl::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    CheckStreams(inStream, outStream);
    UniqueEVPCtx ctx(EVP_CIPHER_CTX_new());

    auto params = CreateChiperParamsFromPassword(password);
    params.encrypt = 1;
    if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt)) {
        throw std::runtime_error("Failed to initialize cipher for encryption");
    }
    ProcessCommand(inStream, outStream, password, ctx.get());
}

void CryptoGuardCtx::PImpl::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    CheckStreams(inStream, outStream);
    UniqueEVPCtx ctx(EVP_CIPHER_CTX_new());

    auto params = CreateChiperParamsFromPassword(password);
    params.encrypt = 0;
    if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt)) {
        throw std::runtime_error("Failed to initialize cipher for decryption");
    }
    ProcessCommand(inStream, outStream, password, ctx.get());
}

void CryptoGuardCtx::PImpl::ProcessCommand(std::iostream &inStream, std::iostream &outStream, std::string_view password,
                                           EVP_CIPHER_CTX *ctx) {
    std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
    std::vector<unsigned char> inBuf(16);
    int outLen;

    while (inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size()) || inStream.gcount() > 0) {
        if (!inStream.good() && !inStream.eof()) {
            throw std::runtime_error("Input stream error during reading");
        }
        int bytesRead = static_cast<int>(inStream.gcount());
        if (!EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), bytesRead)) {
            throw std::runtime_error("Encryption failed during update");
        }

        if (!outStream.good()) {
            throw std::runtime_error("Output stream error before writing");
        }
        outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
        if (!outStream.good()) {
            throw std::runtime_error("Output stream error after writing");
        }

        if (!inStream && !inStream.eof())
            break;
    }

    if (!EVP_CipherFinal_ex(ctx, outBuf.data(), &outLen)) {
        throw std::runtime_error("Failed to complete command. Wrong password");
    }
    outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
}
AesCipherParams CryptoGuardCtx::PImpl::CreateChiperParamsFromPassword(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                params.key.data(), params.iv.data());

    if (result == 0) {
        throw std::runtime_error{"Failed to create a key from password"};
    }

    return params;
}
CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<PImpl>()) {}
CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}

}  // namespace CryptoGuard
