#include "cmd_options.h"
#include <gtest/gtest.h>
TEST(ProgramOptions, HelpTest) {
    const char *argv[] = {"program", "--help"};
    CryptoGuard::ProgramOptions op;

    testing::internal::CaptureStdout();
    op.Parse(2, const_cast<char **>(argv));
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_NE(output.find("Allowed options"), std::string::npos);
    EXPECT_NE(output.find("--help"), std::string::npos);
    EXPECT_NE(output.find("--command"), std::string::npos);
    EXPECT_NE(output.find("--input"), std::string::npos);
    EXPECT_NE(output.find("--output"), std::string::npos);
    EXPECT_NE(output.find("--password"), std::string::npos);
    EXPECT_EQ(op.IsValid(), true);
}

TEST(ProgramOptions, CorrectDecryptInput) {
    const char *argv[] = {"program",  "--command",  "decrypt",    "--input", "input.txt",
                          "--output", "output.txt", "--password", "secret"};
    CryptoGuard::ProgramOptions op;
    op.Parse(9, const_cast<char **>(argv));

    EXPECT_EQ(op.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(op.GetInputFile(), "input.txt");
    EXPECT_EQ(op.GetOutputFile(), "output.txt");
    EXPECT_EQ(op.GetPassword(), "secret");
    EXPECT_EQ(op.IsValid(), true);
}

TEST(ProgramOptions, FileNotFound) {
    const char *argv[] = {"program",  "--command", "encrypt",    "--input", "nonexistent.txt",
                          "--output", "out.bin",   "--password", "1234"};
    CryptoGuard::ProgramOptions op;

    testing::internal::CaptureStderr();
    op.Parse(9, const_cast<char **>(argv));
    std::string error = testing::internal::GetCapturedStderr();

    EXPECT_NE(error.find("not found"), std::string::npos);
    EXPECT_EQ(op.IsValid(), false);
}

TEST(ProgramOptions, CorrectEncryptInput) {
    const char *argv[] = {"program",  "--command", "encrypt",    "--input", "input.txt",
                          "--output", "out.bin",   "--password", "1234"};
    CryptoGuard::ProgramOptions op;

    op.Parse(9, const_cast<char **>(argv));

    EXPECT_EQ(op.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(op.GetInputFile(), "input.txt");
    EXPECT_EQ(op.GetOutputFile(), "out.bin");
    EXPECT_EQ(op.GetPassword(), "1234");
    EXPECT_EQ(op.IsValid(), true);
}

TEST(ProgramOptions, MissingOutputFileInput) {
    const char *argv[] = {"program", "--command", "encrypt", "--input", "input.txt", "--password", "1234"};
    CryptoGuard::ProgramOptions op;
    testing::internal::CaptureStderr();

    op.Parse(7, const_cast<char **>(argv));
    std::string error = testing::internal::GetCapturedStderr();

    EXPECT_EQ(op.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(op.GetInputFile(), "input.txt");
    EXPECT_EQ(op.GetOutputFile(), "");
    EXPECT_EQ(op.GetPassword(), "1234");
    EXPECT_NE(error.find("Output file is required for encrypt/decrypt"), std::string::npos);
    EXPECT_EQ(op.IsValid(), false);
}

TEST(ProgramOptions, MissingPasswordInput) {
    const char *argv[] = {"program", "--command", "encrypt", "--input", "input.txt", "--output", "out.bin"};
    CryptoGuard::ProgramOptions op;
    testing::internal::CaptureStderr();

    op.Parse(7, const_cast<char **>(argv));
    std::string error = testing::internal::GetCapturedStderr();

    EXPECT_EQ(op.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(op.GetInputFile(), "input.txt");
    EXPECT_EQ(op.GetOutputFile(), "out.bin");
    EXPECT_EQ(op.GetPassword(), "");
    EXPECT_NE(error.find("Password is required for encrypt/decrypt"), std::string::npos);
    EXPECT_EQ(op.IsValid(), false);
}

TEST(ProgramOptions, ChecksumSuccess) {
    const char *argv[] = {"program", "--command", "checksum", "--input", "input.txt"};
    CryptoGuard::ProgramOptions op;
    op.Parse(5, const_cast<char **>(argv));

    ASSERT_TRUE(op.IsValid());
    EXPECT_EQ(op.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_TRUE(op.GetOutputFile().empty());
    EXPECT_TRUE(op.GetPassword().empty());
}

TEST(ProgramOptions, MissingInput) {
    const char *argv[] = {"program", "--command", "encrypt", "--output", "out", "--password", "p"};
    CryptoGuard::ProgramOptions op;

    testing::internal::CaptureStderr();
    op.Parse(7, const_cast<char **>(argv));
    std::string err = testing::internal::GetCapturedStderr();

    EXPECT_FALSE(op.IsValid());
    EXPECT_NE(err.find("the option '--input' is required but missing"), std::string::npos);
}

TEST(ProgramOptions, UnknownOption) {
    const char *argv[] = {"program", "--unknown-option", "value"};
    CryptoGuard::ProgramOptions op;

    testing::internal::CaptureStderr();
    op.Parse(3, const_cast<char **>(argv));
    std::string error = testing::internal::GetCapturedStderr();

    EXPECT_NE(error.find("unrecognised option"), std::string::npos);
    EXPECT_FALSE(op.IsValid());
}

TEST(ProgramOptions, InvalidCommandValue) {
    const char *argv[] = {"program", "--command", "invalid_command", "--input", "file.txt"};
    CryptoGuard::ProgramOptions op;

    testing::internal::CaptureStderr();
    op.Parse(5, const_cast<char **>(argv));
    std::string error = testing::internal::GetCapturedStderr();

    EXPECT_NE(error.find("unknown command"), std::string::npos);
    EXPECT_FALSE(op.IsValid());
}

TEST(ProgramOptions, MissingOptionValue) {
    const char *argv[] = {"program", "--command"};
    CryptoGuard::ProgramOptions op;

    testing::internal::CaptureStderr();
    op.Parse(2, const_cast<char **>(argv));
    std::string error = testing::internal::GetCapturedStderr();

    EXPECT_NE(error.find("command"), std::string::npos);
    EXPECT_FALSE(op.IsValid());
}

TEST(ProgramOptions, ShortOptions) {
    const char *argv[] = {"program", "-c", "encrypt", "-i", "input.txt", "-o", "out.bin", "-p", "1234"};
    CryptoGuard::ProgramOptions op;

    op.Parse(9, const_cast<char **>(argv));

    EXPECT_TRUE(op.IsValid());
    EXPECT_EQ(op.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(op.GetInputFile(), "input.txt");
    EXPECT_EQ(op.GetOutputFile(), "out.bin");
    EXPECT_EQ(op.GetPassword(), "1234");
}

TEST(ProgramOptions, MixedShortLongOptions) {
    const char *argv[] = {"program", "-c", "checksum", "--input", "input.txt"};
    CryptoGuard::ProgramOptions op;

    op.Parse(5, const_cast<char **>(argv));

    EXPECT_TRUE(op.IsValid());
    EXPECT_EQ(op.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(op.GetInputFile(), "input.txt");
}