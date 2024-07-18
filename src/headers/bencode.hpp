#pragma once

#include "../lib/nlohmann/json.hpp"
#include <string>

namespace bencode {
std::string encode_token(const nlohmann::json &token);
std::string encode_integer(const int64_t &value);
std::string encode_bytes(const std::vector<unsigned char> &value);
std::string encode_string(const std::string &value);
std::string encode_list(const nlohmann::json &array);
std::string encode_dictionary(const nlohmann::json &object);

nlohmann::json decode_integer(const std::string &value);
nlohmann::json decode_string(const std::string &value);
nlohmann::json decode_list(const std::string &value);
nlohmann::json decode_dictionary(const std::string &value);
nlohmann::json decode_bencoded_value(const std::string &encoded_value,
                                     size_t &position);
nlohmann::json decode_bencoded_value(const std::string &encoded_value);
nlohmann::json decode_bencoded_string(const std::string &encoded_string,
                                      size_t &position);
nlohmann::json decode_bencoded_integer(const std::string &encoded_value,
                                       size_t &position);
nlohmann::json decode_bencoded_list(const std::string &encoded_value,
                                    size_t &position);
nlohmann::json decode_bencoded_dictionary(const std::string &encoded_value,
                                          size_t &position);
} // namespace bencode
