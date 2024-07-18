#pragma once

#include "../lib/nlohmann/json.hpp"
#include "message.hpp"
#include <netinet/in.h>
#include <string>
#include <vector>

class CustomSocket {
public:
  CustomSocket(const std::string &ip_addr, const int port);
  ~CustomSocket();

  bool connect_to_server();

  void send_handshake_message(std::vector<unsigned char> &handshake_message);
  void send_peer_message(std::vector<uint8_t> &peer_message);

  std::vector<unsigned char> receive_handshake_message(size_t numBytes);
  PeerMessage recieve_peer_message();

  void close_connection();
  bool prepare_download();
  void download(nlohmann::json &metainfo, std::string &output_file,
                size_t piece_index);
  void download_piece(nlohmann::json &metainfo, std::string &output_file,
                      size_t piece_index,
                      std::vector<std::string> &pieces_hash);
  void download_file(nlohmann::json &metainfo, std::string &output_file);
  std::vector<uint8_t> fetch_piece_blocks(uint32_t filesize,
                                          uint32_t pieces_length,
                                          std::vector<std::string> pieces_hash,
                                          size_t piece_index);
  bool verify_piece(std::vector<std::string> &pieces_hash,
                    std::vector<uint8_t> &piece_data, size_t piece_index);
  void save_to_file(std::string &output_file, std::vector<uint8_t> &data);
  void save_to_file_append(std::string &output_file,
                           std::vector<uint8_t> &data);

private:
  std::string ip_addr;
  int port;
  int sockfd;
  struct sockaddr_in server_addr;

  bool initialize_socket();
};
