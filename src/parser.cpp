#include "headers/parser.hpp"
#include "headers/bencode.hpp"
#include <fstream>

namespace parser {
nlohmann::json parse_torrent_file(const std::string &filename) {

  std::ifstream file(filename, std::ios::binary | std::ios::ate);

  if (!file.is_open()) {
    throw std::runtime_error("Unable to open file: " + filename);
  }

  std::streamsize file_size = file.tellg();
  file.seekg(0, std::ios::beg);

  std::vector<char> buffer(static_cast<size_t>(file_size));

  if (!file.read(buffer.data(), file_size)) {
    throw std::runtime_error("Error reading file: " + filename);
  }

  std::string torrent_data(buffer.begin(), buffer.end());

  return bencode::decode_bencoded_value(torrent_data);
}
} // namespace parser
