#include "headers/network.hpp"
#include "headers/bencode.hpp"
#include "headers/scrypt.hpp"
#include <arpa/inet.h>
#include <cpr/cpr.h>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <vector>

namespace network {
std::vector<Peer> fetch_peer_list(const std::string &tracker_url,
                                  const std::string &info_hash,
                                  const std::string &peer_id, const int port,
                                  const size_t uploaded,
                                  const size_t downloaded, const size_t left,
                                  const int compact) {

  std::string url = tracker_url + "?info_hash=" + info_hash +
                    "&peer_id=" + peer_id + "&port=" + std::to_string(port) +
                    "&uploaded=" + std::to_string(uploaded) +
                    "&downloaded=" + std::to_string(downloaded) +
                    "&left=" + std::to_string(left) +
                    "&compact=" + std::to_string(compact);
  cpr::Response r = cpr::Get(cpr::Url{url});

  if (r.status_code == 200) {
    nlohmann::json::binary_t peers =
        bencode::decode_bencoded_value(r.text)["peers"];
    std::vector<Peer> peer_list = decode_peer_list(peers);
    return peer_list;
  } else {
    throw std::runtime_error("Unable to make http request");
  }
}

std::vector<Peer> decode_peer_list(const nlohmann::json::binary_t &peer_bytes) {
  std::vector<Peer> peer_list;
  if (peer_bytes.size() % 6 != 0) {
    throw std::runtime_error("Invalid peer bytes: " +
                             scrypt::binary_to_hex(peer_bytes));
    return peer_list;
  }

  for (size_t i = 0; i < peer_bytes.size(); i += 6) {
    uint32_t ip_bytes;
    std::memcpy(&ip_bytes, &peer_bytes[i], sizeof(ip_bytes));
    struct in_addr ip_addr;
    ip_addr.s_addr = htonl(ip_bytes);
    std::string rev_ip_address = inet_ntoa(ip_addr);
    std::string ip_address = reverse_ip_addr(rev_ip_address);

    uint16_t port;
    std::memcpy(&port, &peer_bytes[i + 4], sizeof(port));
    port = ntohs(port);

    Peer peer;
    peer.ip_addr = ip_address;
    peer.port = port;
    peer_list.push_back(peer);
  }
  return peer_list;
}

std::string url_encode(const std::string &hex_string) {
  std::string result;
  result.reserve(hex_string.length() + hex_string.length() / 2);
  std::array<bool, 256> unreserved{};
  for (size_t i = '0'; i <= '9'; ++i)
    unreserved[i] = true;
  for (size_t i = 'A'; i <= 'Z'; ++i)
    unreserved[i] = true;
  for (size_t i = 'a'; i <= 'z'; ++i)
    unreserved[i] = true;
  unreserved['-'] = true;
  unreserved['_'] = true;
  unreserved['.'] = true;
  unreserved['~'] = true;
  for (size_t i = 0; i < hex_string.length(); i += 2) {
    std::string byte_str = hex_string.substr(i, 2);
    size_t byte_val = std::stoul(byte_str, nullptr, 16);
    if (unreserved[byte_val]) {
      result += static_cast<char>(byte_val);
    } else {
      result += "%" + byte_str;
    }
  }
  return result;
}

std::string reverse_ip_addr(const std::string &ip_addr) {
  std::istringstream iss(ip_addr);
  std::string token;
  std::string reversed_tokens[4];

  int idx = 0;
  while (std::getline(iss, token, '.')) {
    reversed_tokens[idx++] = token;
  }

  std::string rev_ip_addr = reversed_tokens[3] + "." + reversed_tokens[2] +
                            "." + reversed_tokens[1] + "." + reversed_tokens[0];
  return rev_ip_addr;
}

std::vector<uint8_t> create_interested_message() {
  // const uint8_t INTERESTED_MESSAGE_ID = 2;
  std::vector<uint8_t> interested_message;
  std::vector<uint8_t> payload;
  uint32_t total_length = 4                 // message length (4 bytes)
                          + 1               // message ID (1 byte)
                          + payload.size(); // payload length (variable)

  interested_message.reserve(total_length);

  // actual message length
  uint32_t networkLength = htonl(total_length - 4);

  const uint8_t *lengthBytes =
      reinterpret_cast<const uint8_t *>(&networkLength);
  interested_message.insert(interested_message.end(), lengthBytes,
                            lengthBytes + sizeof(networkLength));

  interested_message.push_back(static_cast<uint8_t>(2));

  interested_message.insert(interested_message.end(), payload.begin(),
                            payload.end());

  return interested_message;
}

std::vector<uint8_t> create_request_message(uint32_t index, uint32_t begin,
                                            uint32_t length) {
  std::vector<uint8_t> request_message;
  std::vector<uint8_t> request_payload;
  // const uint8_t REQUEST_MESSAGE_ID = 6;
  uint32_t index_n = htonl(index);
  uint32_t begin_n = htonl(begin);
  uint32_t length_n = htonl(length);

  uint32_t total_length = 4   // message length (4 bytes)
                          + 1 // message ID (1 byte)
                          +
                          3 * sizeof(uint32_t); // payload length (3 * 4 bytes)
  request_message.reserve(total_length);

  // actual message length
  uint32_t networkLength = htonl(total_length - 4);

  const uint8_t *messageLengthBytes =
      reinterpret_cast<const uint8_t *>(&networkLength);
  request_message.insert(request_message.end(), messageLengthBytes,
                         messageLengthBytes + sizeof(networkLength));

  request_message.push_back(static_cast<uint8_t>(6));

  // add index_n , begin_n, length_n to the payload
  request_payload.reserve(3 * sizeof(uint32_t));

  const uint8_t *indexBytes = reinterpret_cast<const uint8_t *>(&index_n);
  const uint8_t *beginBytes = reinterpret_cast<const uint8_t *>(&begin_n);
  const uint8_t *lengthBytes = reinterpret_cast<const uint8_t *>(&length_n);

  request_payload.insert(request_payload.end(), indexBytes,
                         indexBytes + sizeof(index_n));
  request_payload.insert(request_payload.end(), beginBytes,
                         beginBytes + sizeof(begin_n));
  request_payload.insert(request_payload.end(), lengthBytes,
                         lengthBytes + sizeof(length_n));

  request_message.insert(request_message.end(), request_payload.begin(),
                         request_payload.end());

  return request_message;
}
} // namespace network
