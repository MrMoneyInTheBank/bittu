#pragma once

#include "../lib/nlohmann/json.hpp"
#include <string>

namespace scrypt {
std::string sha1_hash(const std::string &data);
std::string binary_to_hex(const nlohmann::json::binary_t &binary_data);
std::string hex_to_binary(const std::string &hex);
std::vector<std::string>
binary_to_hex_vector(const nlohmann::json::binary_t &binary_data);
std::string bytes_to_hex_string(const std::vector<unsigned char> &bytes);
std::string to_hex_string(const unsigned char *hash, size_t length);
std::string get_sha1_hash_string(const std::vector<uint8_t> &piece_data);
} // namespace scrypt
