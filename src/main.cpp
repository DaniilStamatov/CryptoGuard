#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <iostream>
#include <openssl/evp.h>
#include <print>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;

        CryptoGuard::CryptoGuardCtx cryptoCtx;
        options.Parse(argc, argv);
    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}