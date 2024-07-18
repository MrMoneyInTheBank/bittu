#include "headers/scrypt.hpp"

#include <iostream>
#include <openssl/sha.h>
#include <sstream>

namespace scrypt {

std::string sha1_hash(const std::string &data) {
  unsigned char hash[SHA_DIGEST_LENGTH];
  SHA1(reinterpret_cast<const unsigned char *>(data.c_str()), data.size(),
       hash);

  std::ostringstream result;
  for (const auto &byte : hash) {

    result << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(byte);
  }
  return result.str();
}

std::string binary_to_hex(const nlohmann::json::binary_t &binary_data) {
  std::ostringstream oss;

  for (const auto &byte : binary_data) {
    oss << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(byte);
  }
  oss << std::dec << "\n";
  return oss.str();
}

std::vector<std::string>
binary_to_hex_vector(const nlohmann::json::binary_t &binary_data) {
  std::vector<std::string> res;

  size_t it = 0;
  while (it < binary_data.size()) {
    std::vector<uint8_t> chunk(binary_data.begin() + it,
                               binary_data.begin() + it + 20);
    nlohmann::json::binary_t chunk_bin = chunk;
    res.push_back(scrypt::binary_to_hex(chunk_bin));
    // res.push_back(scrypt::binary_to_hex(std::string(it, it + 20)));
    it += 20;
  }
  return res;
}

std::string hex_to_binary(const std::string &hex) {
  if (hex.length() % 2 != 0) {
    throw std::invalid_argument("Hex string must have an even length");
  }

  std::string binary;
  binary.reserve(hex.length() / 2);

  for (size_t i = 0; i < hex.length(); i += 2) {
    unsigned char byte = std::stoul(hex.substr(i, 2), nullptr, 16);
    binary.push_back(static_cast<char>(byte));
  }

  return binary;
}

std::string bytes_to_hex_string(const std::vector<unsigned char> &bytes) {
  std::ostringstream oss;
  for (unsigned char byte : bytes) {
    oss << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(byte);
  }
  return oss.str();
}

std::string to_hex_string(const unsigned char *hash, size_t length) {
  std::ostringstream oss;
  for (size_t i = 0; i < length; ++i) {
    oss << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(hash[i]);
  }
  return oss.str();
}

std::string get_sha1_hash_string(const std::vector<uint8_t> &piece_data) {
  unsigned char hash[SHA_DIGEST_LENGTH];
  SHA1(piece_data.data(), piece_data.size(), hash);
  return to_hex_string(hash, SHA_DIGEST_LENGTH);
}
} // namespace scrypt
