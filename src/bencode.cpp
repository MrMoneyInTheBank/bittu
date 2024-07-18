#include "headers/bencode.hpp"
#include "lib/nlohmann/json.hpp"
#include <cctype>
#include <stdexcept>

namespace bencode {

std::string encode_integer(const int64_t &value) {
  return "i" + std::to_string(value) + "e";
}

std::string encode_bytes(const std::vector<unsigned char> &value) {
  return std::to_string(value.size()) + ":" +
         std::string(value.begin(), value.end());
}

std::string encode_string(const std::string &value) {
  std::vector<unsigned char> bytes(value.begin(), value.end());
  return encode_bytes(bytes);
}

std::string encode_list(const nlohmann::json &array);
std::string encode_dictionary(const nlohmann::json &object);

std::string encode_token(const nlohmann::json &token) {
  if (token.is_string()) {
    return encode_string(token.get<std::string>());
  } else if (token.is_number_integer()) {
    return encode_integer(token.get<int64_t>());
  } else if (token.is_array()) {
    return encode_list(token);
  } else if (token.is_object()) {
    return encode_dictionary(token);
  } else if (token.is_binary()) {
    return encode_bytes(token.get_binary());
  } else {
    throw std::runtime_error("Unsupported token type in JSON: " + token.dump());
  }
}

std::string encode_list(const nlohmann::json &array) {
  if (!array.is_array()) {
    throw std::runtime_error("Input value must be a JSON array: " +
                             array.dump());
  }

  std::string result = "l";
  for (const auto &token : array) {
    result += encode_token(token);
  }
  return result + "e";
}

std::string encode_dictionary(const nlohmann::json &object) {
  if (!object.is_object()) {
    throw std::runtime_error("Input must be JSON object: " + object.dump());
  }

  std::string result = "d";
  for (auto it = object.begin(); it != object.end(); ++it) {
    result += encode_string(it.key());
    result += encode_token(it.value());
  }
  return result + "e";
}

nlohmann::json decode_bencoded_value(const std::string &encoded_value,
                                     size_t &position);

nlohmann::json decode_bencoded_string(const std::string &encoded_string,
                                      size_t &position) {
  size_t length_prefix = encoded_string.find(':', position);
  if (length_prefix != std::string::npos) {
    std::string string_size_str =
        encoded_string.substr(position, length_prefix - position);
    int64_t string_size_int = std::stoll(string_size_str);
    position = length_prefix + 1 + string_size_int;
    std::string str = encoded_string.substr(length_prefix + 1, string_size_int);

    if (std::any_of(str.begin(), str.end(),
                    [](unsigned char c) { return !std::isprint(c); })) {
      return nlohmann::json::binary(
          std::vector<std::uint8_t>(str.begin(), str.end()));
    } else {
      return nlohmann::json(str);
    }
  } else {
    throw std::runtime_error("Invalid encoded value: " + encoded_string);
  }
}

nlohmann::json decode_bencoded_integer(const std::string &encoded_value,
                                       size_t &position) {
  position++;
  size_t end = encoded_value.find('e', position);
  if (end == std::string::npos) {
    throw std::invalid_argument("Invalid bencoded integer");
  }
  std::string integer_str = encoded_value.substr(position, end - position);
  position = end + 1;
  return std::stoll(integer_str);
}

nlohmann::json decode_bencoded_list(const std::string &encoded_value,
                                    size_t &position) {
  position++;
  nlohmann::json list = nlohmann::json::array();
  while (encoded_value[position] != 'e') {
    list.push_back(decode_bencoded_value(encoded_value, position));
  }
  position++;
  return list;
}

nlohmann::json decode_bencoded_dictionary(const std::string &encoded_value,
                                          size_t &position) {
  position++;
  nlohmann::json dict = nlohmann::json::object();
  while (encoded_value[position] != 'e') {
    nlohmann::json key = decode_bencoded_value(encoded_value, position);
    nlohmann::json value = decode_bencoded_value(encoded_value, position);
    dict[key.get<std::string>()] = value;
  }
  position++;
  return dict;
}

nlohmann::json decode_bencoded_value(const std::string &encoded_value,
                                     size_t &position) {
  if (std::isdigit(encoded_value[position])) {
    return decode_bencoded_string(encoded_value, position);
  } else if (encoded_value[position] == 'i') {
    return decode_bencoded_integer(encoded_value, position);
  } else if (encoded_value[position] == 'l') {
    return decode_bencoded_list(encoded_value, position);
  } else if (encoded_value[position] == 'd') {
    return decode_bencoded_dictionary(encoded_value, position);
  } else {
    throw std::runtime_error("Unhandled encoded value: " + encoded_value);
  }
}

nlohmann::json decode_bencoded_value(const std::string &encoded_value) {
  size_t position = 0;
  return decode_bencoded_value(encoded_value, position);
}

} // namespace bencode
