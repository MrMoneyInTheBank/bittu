#include "headers/custom_socket.hpp"
#include "headers/message.hpp"
#include "headers/scrypt.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

CustomSocket::CustomSocket(const std::string &ip_addr, const int port)
    : ip_addr(ip_addr), port(port), sockfd(-1) {
  std::memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
}

CustomSocket::~CustomSocket() { close_connection(); }

bool CustomSocket::initialize_socket() {
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    std::cerr << "Error: Could not create socket" << std::endl;
    return false;
  }

  if (inet_pton(AF_INET, ip_addr.c_str(), &server_addr.sin_addr) <= 0) {
    std::cerr << "Error: Invalid address/ Address not supported" << std::endl;
    close(sockfd);
    sockfd = -1;
    return false;
  }

  return true;
}

bool CustomSocket::connect_to_server() {
  if (!initialize_socket()) {
    return false;
  }

  if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
      0) {
    std::cerr << "Error: Connection Failed" << std::endl;
    close(sockfd);
    sockfd = -1;
    return false;
  }

  return true;
}

void CustomSocket::send_handshake_message(
    std::vector<unsigned char> &handshake_message) {
  if (::send(sockfd, handshake_message.data(), handshake_message.size(), 0) <
      0) {
    std::cout << "Failed to send message via TCP client" << std::endl;
    throw std::runtime_error("TCP connection failed");
  }
}

void CustomSocket::send_peer_message(std::vector<uint8_t> &peer_message) {

  ssize_t iResult =
      send(this->sockfd, peer_message.data(), peer_message.size(), 0);
  if (iResult < 0) {
    this->close_connection();
    throw std::runtime_error("send failed");
  }
}

std::vector<unsigned char>
CustomSocket::receive_handshake_message(size_t numBytes) {
  std::vector<unsigned char> buffer(numBytes);
  ssize_t bytesRead = ::recv(sockfd, buffer.data(), numBytes, 0);
  if (bytesRead < 0) {
    throw std::runtime_error("Receive failed");
  } else if (bytesRead == 0) {
    throw std::runtime_error("Connection closed by peer");
  }
  buffer.resize(bytesRead);
  return buffer;
}

PeerMessage CustomSocket::recieve_peer_message() {
  if (this->sockfd == 0) {
    throw std::runtime_error("Socket not connected");
  }

  uint32_t messageLength;
  ssize_t iResult =
      recv(this->sockfd, &messageLength, sizeof(messageLength), 0);
  if (iResult < 0) {
    close(this->sockfd);
    throw std::runtime_error("recv failed");
  }

  messageLength = ntohl(messageLength);

  uint8_t messageID;
  iResult = recv(this->sockfd, &messageID, sizeof(messageID), 0);
  if (iResult < 0) {
    close(this->sockfd);
    throw std::runtime_error("recv failed");
  }

  // payload size (total message length - 1 byte for ID part)
  size_t payloadSize = messageLength - 1;

  // Receive the payload
  std::vector<uint8_t> payload(payloadSize);
  size_t totalBytesRead = 0;
  while (totalBytesRead < payloadSize) {
    ssize_t bytesRead = recv(this->sockfd, payload.data() + totalBytesRead,
                             payloadSize - totalBytesRead, 0);
    if (bytesRead <= 0) {
      throw std::runtime_error("Failed to receive complete payload");
    }
    totalBytesRead += bytesRead;
  }
  return PeerMessage(static_cast<PEER_MESSAGE_TYPE>(messageID), messageLength,
                     payload);
}

void CustomSocket::close_connection() {
  if (sockfd != -1) {
    close(sockfd);
    sockfd = -1;
  }
}

void CustomSocket::download(nlohmann::json &metainfo, std::string &output_file,
                            size_t piece_index) {
  uint32_t filesize = metainfo["info"]["length"];
  uint32_t pieces_length = metainfo["info"]["piece length"];

  nlohmann::json::binary_t binary_pieces_hash =
      metainfo["info"]["pieces"].get<nlohmann::json::binary_t>();
  std::vector<std::string> pieces_hash =
      scrypt::binary_to_hex_vector(binary_pieces_hash);

  PeerMessage bitfield_message = this->recieve_peer_message();
  if (bitfield_message.get_type() != PEER_MESSAGE_TYPE::BITFIELD) {
    throw std::runtime_error(
        "Expected BITFIELD(ID=5) message, but received message of ID: " +
        std::to_string(static_cast<int>(bitfield_message.get_type())));
  }

  std::vector<uint8_t> interested_message =
      PeerMessage::create_interested_message();
  this->send_peer_message(interested_message);

  PeerMessage unchoke_response = this->recieve_peer_message();
  if (unchoke_response.get_type() != PEER_MESSAGE_TYPE::UNCHOKE) {
    throw std::runtime_error(
        "Expected UNCHOKE message(ID=1), but received  message of ID: " +
        std::to_string(static_cast<int>(unchoke_response.get_type())));
  }

  std::vector<uint8_t> piece_data = this->fetch_piece_blocks(
      filesize, pieces_length, pieces_hash, piece_index);

  if (this->verify_piece(pieces_hash, piece_data, piece_index)) {
    this->save_to_file(output_file, piece_data);
  } else {
    throw std::runtime_error("unverfied piece downloaded.");
  }
}

void CustomSocket::download_piece(nlohmann::json &metainfo,
                                  std::string &output_file, size_t piece_index,
                                  std::vector<std::string> &pieces_hash) {
  uint32_t filesize = metainfo["info"]["length"];
  uint32_t pieces_length = metainfo["info"]["piece length"];

  std::vector<uint8_t> piece_data = this->fetch_piece_blocks(
      filesize, pieces_length, pieces_hash, piece_index);

  if (this->verify_piece(pieces_hash, piece_data, piece_index)) {
    this->save_to_file_append(output_file, piece_data);
  } else {
    throw std::runtime_error("unverfied piece downloaded.");
  }
}

void CustomSocket::download_file(nlohmann::json &metainfo,
                                 std::string &output_file) {

  uint32_t filesize = metainfo["info"]["length"];
  uint32_t pieces_length = metainfo["info"]["piece length"];

  nlohmann::json::binary_t binary_pieces_hash =
      metainfo["info"]["pieces"].get<nlohmann::json::binary_t>();
  std::vector<std::string> pieces_hash =
      scrypt::binary_to_hex_vector(binary_pieces_hash);

  PeerMessage bitfield_message = this->recieve_peer_message();
  if (bitfield_message.get_type() != PEER_MESSAGE_TYPE::BITFIELD) {
    throw std::runtime_error(
        "Expected BITFIELD(ID=5) message, but received message of ID: " +
        std::to_string(static_cast<int>(bitfield_message.get_type())));
  }

  std::vector<uint8_t> interested_message =
      PeerMessage::create_interested_message();
  this->send_peer_message(interested_message);

  PeerMessage unchoke_response = this->recieve_peer_message();
  if (unchoke_response.get_type() != PEER_MESSAGE_TYPE::UNCHOKE) {
    throw std::runtime_error(
        "Expected UNCHOKE message(ID=1), but received  message of ID: " +
        std::to_string(static_cast<int>(unchoke_response.get_type())));
  }

  for (size_t i = 0; i < pieces_hash.size(); i++) {
    this->download_piece(metainfo, output_file, i, pieces_hash);
  }
};

void CustomSocket::save_to_file(std::string &output_file,
                                std::vector<uint8_t> &data) {
  std::ofstream file(output_file, std::ios::binary);
  file.write(reinterpret_cast<char const *>(data.data()), data.size());
  file.close();
}

void CustomSocket::save_to_file_append(std::string &output_file,
                                       std::vector<uint8_t> &data) {
  std::ofstream file(output_file, std::ios::binary | std::ios::app);
  file.write(reinterpret_cast<char const *>(data.data()), data.size());
  file.close();
}

std::vector<uint8_t>
CustomSocket::fetch_piece_blocks(uint32_t filesize, uint32_t pieces_length,
                                 std::vector<std::string> pieces_hash,
                                 size_t piece_index) {
  const uint32_t BLOCK_SIZE = 16 * 1024;
  uint32_t block_index = 0;
  uint32_t block_offset = 0;
  uint32_t current_block_length = BLOCK_SIZE;

  uint32_t piece_length;
  if (piece_index >= pieces_hash.size()) {
    throw std::runtime_error("Invalid piece index");
  } else if (piece_index == pieces_hash.size() - 1) {

    piece_length = filesize % pieces_length;
  } else {
    piece_length = pieces_length;
  }

  std::vector<uint8_t> piece_data(piece_length);
  while (block_index * BLOCK_SIZE < piece_length) {
    // adjust block length for the last block
    if (block_offset + BLOCK_SIZE > piece_length) {
      current_block_length = piece_length - block_offset;
    }

    std::vector<uint8_t> request_message = PeerMessage::create_request_message(
        piece_index, block_offset, current_block_length);
    this->send_peer_message(request_message);

    PeerMessage piece_response = this->recieve_peer_message();

    if (piece_response.get_type() == PEER_MESSAGE_TYPE::CHOKE) {
      break;
    }

    if (piece_response.get_type() != PEER_MESSAGE_TYPE::PIECE) {
      throw std::runtime_error(
          "Expected PIECE message(ID=7), but received message of ID: " +
          std::to_string(static_cast<int>(piece_response.get_type())) +
          " at block index: " + std::to_string(block_index) +
          " and block offset: " + std::to_string(block_offset) +
          " with length: " + std::to_string(current_block_length));
    }

    Block block = piece_response.get_block();
    std::copy(block.data.begin(), block.data.end(),
              piece_data.begin() + block.begin);

    block_index++;
    block_offset += BLOCK_SIZE;
  }

  return piece_data;
}

std::string trim_trailing_whitespace(const std::string &str) {
  size_t end = str.find_last_not_of(" \t\n\r\f\v");
  return (end == std::string::npos) ? "" : str.substr(0, end + 1);
}

bool CustomSocket::verify_piece(std::vector<std::string> &pieces_hash,
                                std::vector<uint8_t> &piece_data,
                                size_t piece_index) {
  if (piece_index >= pieces_hash.size()) {
    return false;
  }
  std::string hash_string = scrypt::get_sha1_hash_string(piece_data);
  return hash_string == trim_trailing_whitespace(pieces_hash[piece_index]);
}
