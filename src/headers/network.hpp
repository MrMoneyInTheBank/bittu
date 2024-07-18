#pragma once

#include "../lib/nlohmann/json.hpp"
#include "peers.hpp"
#include <string>

namespace network {
std::vector<Peer> fetch_peer_list(const std::string &tracker_url,
                                  const std::string &info_hash,
                                  const std::string &peer_id, const int port,
                                  const size_t uploaded,
                                  const size_t downloaded, const size_t left,
                                  const int compact);
std::vector<Peer> decode_peer_list(const nlohmann::json::binary_t &peer_bytes);
std::string url_encode(const std::string &hex_string);
std::string reverse_ip_addr(const std::string &ip_addr);
std::vector<uint8_t> create_interested_message();
std::vector<uint8_t> create_request_message(uint32_t index, uint32_t begin,
                                            uint32_t length);
} // namespace network
