#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <stdexcept>

class CryptoGuardCtxStringStreamTest : public ::testing::Test {
protected:
    CryptoGuard::CryptoGuardCtx ctx;
    std::string test_data = "Hello, World! This is test data for encryption. 12345";
};

TEST_F(CryptoGuardCtxStringStreamTest, SimpleEncrypt) {
    std::stringstream input(test_data);
    std::stringstream output;

    ASSERT_NO_THROW(ctx.EncryptFile(input, output, "password"));

    std::string encrypted = output.str();

    ASSERT_FALSE(encrypted.empty());
    ASSERT_NE(encrypted, test_data);

    ASSERT_GE(encrypted.size(), test_data.size());
}

TEST_F(CryptoGuardCtxStringStreamTest, DifferentPasswords) {
    std::stringstream input(test_data);
    std::stringstream input2(test_data);
    std::stringstream output;
    std::stringstream output2;

    ASSERT_NO_THROW(ctx.EncryptFile(input, output, "password"));
    ASSERT_NO_THROW(ctx.EncryptFile(input2, output2, "12345678"));
    ASSERT_NE(output.str(), output2.str());
}

TEST_F(CryptoGuardCtxStringStreamTest, EmptyStream) {
    std::stringstream input;
    std::stringstream output;

    ASSERT_THROW(ctx.EncryptFile(input, output, "password"), std::runtime_error);
}

TEST_F(CryptoGuardCtxStringStreamTest, BadStream) {
    std::stringstream input(test_data);
    std::stringstream output;
    input.setstate(std::ios::badbit);

    ASSERT_THROW(ctx.EncryptFile(input, output, "password"), std::runtime_error);
}

TEST_F(CryptoGuardCtxStringStreamTest, SamePasswordSameResult) {
    std::stringstream input1(test_data);
    std::stringstream input2(test_data);
    std::stringstream output1;
    std::stringstream output2;

    ASSERT_NO_THROW(ctx.EncryptFile(input1, output1, "password"));
    ASSERT_NO_THROW(ctx.EncryptFile(input2, output2, "password"));

    ASSERT_EQ(output1.str(), output2.str());
}

TEST_F(CryptoGuardCtxStringStreamTest, TestEncryptDecrypt) {
    std::stringstream input(test_data);
    std::stringstream encrypted;
    std::stringstream decrypted;

    ASSERT_NO_THROW(ctx.EncryptFile(input, encrypted, "password"));

    ASSERT_NO_THROW(ctx.DecryptFile(encrypted, decrypted, "password"));

    ASSERT_EQ(decrypted.str(), test_data);
}

TEST_F(CryptoGuardCtxStringStreamTest, DecryptWithWrongPassword) {
    std::stringstream input(test_data);
    std::stringstream encrypted;
    std::stringstream decrypted;

    ASSERT_NO_THROW(ctx.EncryptFile(input, encrypted, "right_password"));

    ASSERT_THROW(ctx.DecryptFile(encrypted, decrypted, "wrong_password"), std::runtime_error);
}

TEST_F(CryptoGuardCtxStringStreamTest, DecryptEmptyEncryptedData) {
    std::stringstream encrypted;
    std::stringstream decrypted;

    ASSERT_THROW(ctx.DecryptFile(encrypted, decrypted, "password"), std::runtime_error);
}
TEST_F(CryptoGuardCtxStringStreamTest, DecryptPartialData) {
    std::stringstream input(test_data);
    std::stringstream encrypted;
    std::stringstream decrypted;

    ctx.EncryptFile(input, encrypted, "password");

    std::string full_encrypted = encrypted.str();
    std::string partial_encrypted = full_encrypted.substr(0, full_encrypted.size() / 2);
    std::stringstream partial_stream(partial_encrypted);

    ASSERT_THROW(ctx.DecryptFile(partial_stream, decrypted, "password"), std::runtime_error);
}