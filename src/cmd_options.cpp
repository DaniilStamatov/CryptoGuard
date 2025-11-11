#include "cmd_options.h"
#include <boost/program_options/errors.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/value_semantic.hpp>
#include <boost/program_options/variables_map.hpp>
#include <fstream>
#include <iostream>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()("help", "Help message")("command,c", po::value<std::string>()->required(),
                                                "Command: encrypt, decrypt, checksum")(
        "input,i", po::value<std::string>()->required(), "Path to input file")(
        "output,o", po::value<std::string>(), "Path to output file")("password,p", po::value<std::string>(),
                                                                     "Password for encryption/decryption");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    valid_ = false;
    help_requested_ = false;
    if (!TryParseCommandLine(argc, argv)) {
        return;
    }

    valid_ = ValidateSemantics();
}

bool ProgramOptions::TryParseCommandLine(int argc, char *argv[]) noexcept {
    try {
        po::store(po::parse_command_line(argc, argv, desc_), vm_);

        if (vm_.count("help")) {
            std::cout << desc_ << "\n";
            help_requested_ = true;
            return true;
        }
        po::notify(vm_);
        command_ = StringToCommandType(vm_["command"].as<std::string>());
        if (command_ == COMMAND_TYPE::UNKNOWN) {
            std::cerr << "[ERROR]: unknown command " << vm_["command"].as<std::string>() << "\n";
            return false;
        }
        inputFile_ = vm_["input"].as<std::string>();

        if (vm_.count("output")) {
            outputFile_ = vm_["output"].as<std::string>();
        }
        if (vm_.count("password")) {
            password_ = vm_["password"].as<std::string>();
        }
        return true;
    } catch (const po::error &e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
        return false;
    }
}

bool ProgramOptions::ValidateSemantics() noexcept {
    if (help_requested_)
        return true;
    std::ifstream test_file(inputFile_);
    if (!test_file) {
        std::cerr << "[ERROR]: file " << inputFile_ << " not found\n";
        return false;
    }

    if (command_ == COMMAND_TYPE::ENCRYPT || command_ == COMMAND_TYPE::DECRYPT) {
        if (outputFile_.empty()) {
            std::cerr << "[ERROR] Output file is required for encrypt/decrypt\n";
            return false;
        }
        if (password_.empty()) {
            std::cerr << "[ERROR] Password is required for encrypt/decrypt\n";
            return false;
        }
    }
    return true;
}

ProgramOptions::COMMAND_TYPE ProgramOptions::StringToCommandType(std::string_view command) {
    auto it = commandMapping_.find(command);
    return it != commandMapping_.end() ? it->second : COMMAND_TYPE::UNKNOWN;
}

}  // namespace CryptoGuard
