#pragma once

#include "scrypt.hpp"
#include <arpa/inet.h>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

struct HandshakeMessage {
  std::string info_hash;
  std::string peer_id;
  std::vector<unsigned char> body;

  HandshakeMessage(std::string &info_hash, std::string &peer_id)
      : info_hash(info_hash), peer_id(peer_id) {
    body = build_handshake_message();
  };

  std::vector<unsigned char> build_handshake_message() {
    std::string hex_info_hash = scrypt::hex_to_binary(info_hash);

    if (hex_info_hash.size() != 20) {
      throw std::runtime_error(
          "Info hash must be 20 bytes in handshake message");
    }

    std::vector<unsigned char> handshake(68, 0);
    handshake[0] = 19;
    const char protocol[] = "BitTorrent protocol";
    std::memcpy(&handshake[1], protocol, 19);
    std::memcpy(&handshake[28], hex_info_hash.data(), 20);
    std::memcpy(&handshake[48], peer_id.data(), 20);

    return handshake;
  }
};

struct Block {
  uint32_t index;
  uint32_t begin;
  std::vector<uint8_t> data;
};

enum class PEER_MESSAGE_TYPE {
  CHOKE,
  UNCHOKE,
  INTERESTED,
  NOT_INTERESTED,
  HAVE,
  BITFIELD,
  REQUEST,
  PIECE,
  CANCEL
};

struct PeerMessage {
  PEER_MESSAGE_TYPE type;
  uint32_t length;
  std::vector<uint8_t> payload;

  PeerMessage(PEER_MESSAGE_TYPE type, uint32_t length,
              std::vector<uint8_t> payload)
      : type(type), length(length), payload(payload) {}

  PEER_MESSAGE_TYPE get_type() { return this->type; }
  uint32_t get_length() { return this->length; }
  std::vector<uint8_t> get_payload() { return this->payload; }

  Block get_block() {
    Block result;

    if (this->type != PEER_MESSAGE_TYPE::PIECE) {
      throw std::runtime_error("Not a PIECE message");
    }

    // payload is of the form: <index><begin><block>
    constexpr uint32_t INDEX_OFFSET = 0;
    constexpr uint32_t BEGIN_OFFSET = 4;
    constexpr uint32_t DATA_OFFSET = 8;

    if (this->payload.size() < DATA_OFFSET) {
      throw std::runtime_error("Piece message payload too short");
    }

    result.index = ntohl(*reinterpret_cast<const uint32_t *>(
        this->payload.data() + INDEX_OFFSET));

    result.begin = ntohl(*reinterpret_cast<const uint32_t *>(
        this->payload.data() + BEGIN_OFFSET));

    result.data = std::vector<uint8_t>(this->payload.begin() + DATA_OFFSET,
                                       this->payload.end());

    return result;
  }

  static std::vector<uint8_t> create_interested_message() {
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

    interested_message.push_back(
        static_cast<uint8_t>(PEER_MESSAGE_TYPE::INTERESTED));

    interested_message.insert(interested_message.end(), payload.begin(),
                              payload.end());

    return interested_message;
  }

  static std::vector<uint8_t>
  create_request_message(uint32_t index, uint32_t begin, uint32_t length) {
    std::vector<uint8_t> request_message;
    std::vector<uint8_t> request_payload;
    // const uint8_t REQUEST_MESSAGE_ID = 6;
    uint32_t index_n = htonl(index);
    uint32_t begin_n = htonl(begin);
    uint32_t length_n = htonl(length);

    uint32_t total_length =
        4                       // message length (4 bytes)
        + 1                     // message ID (1 byte)
        + 3 * sizeof(uint32_t); // payload length (3 * 4 bytes)
    request_message.reserve(total_length);

    // actual message length
    uint32_t networkLength = htonl(total_length - 4);

    const uint8_t *messageLengthBytes =
        reinterpret_cast<const uint8_t *>(&networkLength);
    request_message.insert(request_message.end(), messageLengthBytes,
                           messageLengthBytes + sizeof(networkLength));

    request_message.push_back(static_cast<uint8_t>(PEER_MESSAGE_TYPE::REQUEST));

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
};
