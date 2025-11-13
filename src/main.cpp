#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <exception>
#include <fstream>
#include <iostream>
#include <print>
int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);
        if (!options.IsValid() || options.HelpRequested())
            return 0;
        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using CT = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        auto command = options.GetCommand();
        auto input_file = options.GetInputFile();
        auto output_file = options.GetOutputFile();
        auto password = options.GetPassword();

        std::fstream input(input_file, std::ios::in | std::ios::binary);

        if (command == CT::ENCRYPT || command == CT::DECRYPT) {
            std::fstream output(output_file, std::ios::out | std::ios::binary);

            if (command == CT::ENCRYPT) {
                cryptoCtx.EncryptFile(input, output, password);
                std::println("Encrypted: {} -> {}", input_file, output_file);
            } else {
                cryptoCtx.DecryptFile(input, output, password);
                std::println("Decrypted: {} -> {}", input_file, output_file);
            }
        } else if (command == CT::CHECKSUM) {
            auto checksum = cryptoCtx.CalculateChecksum(input);
            std::println("Checksum for {}: {}", input_file, checksum);
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }
    return 0;
}