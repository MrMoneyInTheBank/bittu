#pragma once

#include "../lib/nlohmann/json.hpp"
#include <string>

namespace parser {
nlohmann::json parse_torrent_file(const std::string &filename);
} // namespace parser
