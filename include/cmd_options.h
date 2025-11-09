#pragma once

#include <boost/program_options.hpp>
#include <string>
#include <unordered_map>

namespace CryptoGuard {
namespace po = boost::program_options;
class ProgramOptions {
public:
    ProgramOptions();
    ~ProgramOptions();

    enum class COMMAND_TYPE { ENCRYPT, DECRYPT, CHECKSUM, UNKNOWN };

    void Parse(int argc, char *argv[]);

    [[nodiscard]] COMMAND_TYPE GetCommand() const { return command_; }
    [[nodiscard]] std::string GetInputFile() const { return inputFile_; }
    [[nodiscard]] std::string GetOutputFile() const { return outputFile_; }
    [[nodiscard]] std::string GetPassword() const { return password_; }
    [[nodiscard]] bool IsValid() const { return valid_; }

private:
    bool TryParseCommandLine(int argc, char *argv[]) noexcept;

    bool ValidateSemantics() noexcept;

    COMMAND_TYPE StringToCommandType(std::string_view command);
    COMMAND_TYPE command_;
    const std::unordered_map<std::string_view, COMMAND_TYPE> commandMapping_ = {
        {"encrypt", ProgramOptions::COMMAND_TYPE::ENCRYPT},
        {"decrypt", ProgramOptions::COMMAND_TYPE::DECRYPT},
        {"checksum", ProgramOptions::COMMAND_TYPE::CHECKSUM},
    };

    std::string inputFile_;
    std::string outputFile_;
    std::string password_;
    bool valid_;
    bool help_requested_;
    po::options_description desc_;
    po::variables_map vm_;
};

}  // namespace CryptoGuard
