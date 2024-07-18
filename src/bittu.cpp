#include "headers/bittu.hpp"
#include "headers/bencode.hpp"
#include "headers/custom_socket.hpp"
#include "headers/message.hpp"
#include "headers/network.hpp"
#include "headers/parser.hpp"
#include "headers/scrypt.hpp"
#include <exception>
#include <iostream>
#include <string>

namespace bittu {
int decode_command(int argc, char *argv[]) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
    return 1;
  }

  std::string encoded_value = argv[2];
  try {
    std::cout << bencode::decode_bencoded_value(encoded_value) << std::endl;
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    return 1;
  }
  return 0;
}

int info_command(int argc, char *argv[]) {
  if (argc < 3) {
    std::cerr << "Usage " << argv[0] << " info <torrent_file>" << std::endl;
    return 1;
  }

  std::string filename = argv[2];

  try {
    nlohmann::json torrent_metadata = parser::parse_torrent_file(filename);
    std::string bencoded_torrent_metadata_info =
        bencode::encode_dictionary(torrent_metadata["info"]);
    nlohmann::json::binary_t pieces_binary_data =
        torrent_metadata["info"]["pieces"].get<nlohmann::json::binary_t>();

    std::string tracker_url = torrent_metadata["announce"].get<std::string>();
    size_t filesize = torrent_metadata["info"]["length"];
    std::string info_hash = scrypt::sha1_hash(bencoded_torrent_metadata_info);
    size_t piece_length = torrent_metadata["info"]["piece length"];
    std::string piece_hashes = scrypt::binary_to_hex(pieces_binary_data);

    std::cout << std::endl;
    std::cout << "Tracker URL: " << tracker_url << std::endl;
    std::cout << "Length: " << filesize << std::endl;
    std::cout << "Info Hash: " << info_hash << std::endl;
    std::cout << "Piece Length: " << piece_length;
    std::cout << "Piece Hashes: \n" << piece_hashes << std::endl;
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    return 1;
  }
  return 0;
}

int peers_command(int argc, char *argv[]) {
  if (argc < 3) {
    std::cerr << "Usage: " << argv[0] << " peers <torrent_file>" << std::endl;
    return 1;
  }

  std::string torrent_file = argv[2];

  try {
    nlohmann::json torrent_metadata = parser::parse_torrent_file(torrent_file);
    size_t filesize = torrent_metadata["info"]["length"];
    std::string bencoded_torrent_metadata_info =
        bencode::encode_dictionary(torrent_metadata["info"]);
    std::string info_hash = scrypt::sha1_hash(bencoded_torrent_metadata_info);

    std::string tracker_url = torrent_metadata["announce"].get<std::string>();
    std::string encoded_info_hash = network::url_encode(info_hash);
    std::string peer_id = "12345678900987654321";
    size_t port = 6881, uploaded = 0, downloaded = 0, left = filesize;
    int compact = 1;

    std::vector<Peer> peer_list =
        network::fetch_peer_list(tracker_url, encoded_info_hash, peer_id, port,
                                 uploaded, downloaded, left, compact);
    for (const Peer &p : peer_list) {
      std::cout << p.ip_addr << ":" << p.port << std::endl;
    }
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    return 1;
  }
  return 0;
}

int handshake_command(int argc, char *argv[]) {
  if (argc < 4) {
    std::cerr << "Usage: " << argv[0]
              << " handshake <torrent_file> <peer_ip>:<peer_port>" << std::endl;
    return 1;
  }

  std::string torrent_file = argv[2];

  try {
    nlohmann::json torrent_metadata = parser::parse_torrent_file(torrent_file);
    std::string bencoded_torrent_metadata_info =
        bencode::encode_dictionary(torrent_metadata["info"]);
    std::string info_hash = scrypt::sha1_hash(bencoded_torrent_metadata_info);

    std::string ip_addr = argv[3];
    size_t split_index = ip_addr.find(":");
    std::string peer_ip = ip_addr.substr(0, split_index);
    int peer_port = std::stoi(ip_addr.substr(split_index + 1));

    std::string protocol = "BitTorrent protocol";
    std::string peer_id = "00112233445566778899";

    CustomSocket client_socket(peer_ip, peer_port);

    if (client_socket.connect_to_server()) {

      HandshakeMessage handshake(info_hash, peer_id);
      client_socket.send_handshake_message(handshake.body);

      size_t responseSize = 68;
      std::vector<unsigned char> response =
          client_socket.receive_handshake_message(responseSize);

      size_t peerIdSize = 20;
      std::vector<unsigned char> peerId(response.end() - peerIdSize,
                                        response.end());

      std::string peerIdHexString = scrypt::bytes_to_hex_string(peerId);
      std::cout << "Peer ID: " << peerIdHexString << std::endl;
      std::cout << std::dec;
    } else {
      throw std::runtime_error("Could not establish TCP connection to peer.");
    }
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    return 1;
  }
  return 0;
};

int download_piece_command(int argc, char *argv[]) {
  if (argc < 6) {
    std::cerr << "Usage: " << argv[0]
              << " download_piece -o <output_file> <torrent file> <piece_index>"
              << std::endl;
    return 1;
  }

  std::string output_file = argv[3];
  std::string torrent_file = argv[4];
  size_t piece_index = std::stoul(argv[5]);

  try {
    nlohmann::json torrent_metadata = parser::parse_torrent_file(torrent_file);
    size_t filesize = torrent_metadata["info"]["length"];
    std::string bencoded_torrent_metadata_info =
        bencode::encode_dictionary(torrent_metadata["info"]);
    std::string info_hash = scrypt::sha1_hash(bencoded_torrent_metadata_info);

    std::string tracker_url = torrent_metadata["announce"].get<std::string>();
    std::string encoded_info_hash = network::url_encode(info_hash);
    std::string peer_id = "12345678900987654321";
    size_t port = 6881, uploaded = 0, downloaded = 0, left = filesize;
    int compact = 1;

    std::vector<Peer> peer_list =
        network::fetch_peer_list(tracker_url, encoded_info_hash, peer_id, port,
                                 uploaded, downloaded, left, compact);

    Peer peer = peer_list[0];
    std::string peer_ip = peer.ip_addr;
    int peer_port = peer.port;

    std::string protocol = "BitTorrent protocol";
    CustomSocket client_socket(peer_ip, peer_port);

    if (client_socket.connect_to_server()) {
      HandshakeMessage handshake(info_hash, peer_id);
      client_socket.send_handshake_message(handshake.body);

      size_t responseSize = 68;
      std::vector<unsigned char> response =
          client_socket.receive_handshake_message(responseSize);

      size_t peerIdSize = 20;
      std::vector<unsigned char> peerId(response.end() - peerIdSize,
                                        response.end());

      std::string peerIdHexString = scrypt::bytes_to_hex_string(peerId);

      try {
        client_socket.download(torrent_metadata, output_file, piece_index);
        std::cout << "Downloaded piece " << piece_index << " to " << output_file
                  << std::endl;
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
  }
  return 0;
}

int download(int argc, char *argv[]) {
  if (argc < 5) {
    std::cerr << "Usage: " << argv[0]
              << " download -o <output_file> <torrent file>" << std::endl;
    return 1;
  }

  std::string output_file = argv[3];
  std::string torrent_file = argv[4];

  try {

    nlohmann::json torrent_metadata = parser::parse_torrent_file(torrent_file);
    size_t filesize = torrent_metadata["info"]["length"];
    std::string bencoded_torrent_metadata_info =
        bencode::encode_dictionary(torrent_metadata["info"]);
    std::string info_hash = scrypt::sha1_hash(bencoded_torrent_metadata_info);

    std::string tracker_url = torrent_metadata["announce"].get<std::string>();
    std::string encoded_info_hash = network::url_encode(info_hash);
    std::string peer_id = "12345678900987654321";
    size_t port = 6881, uploaded = 0, downloaded = 0, left = filesize;
    int compact = 1;

    std::vector<Peer> peer_list =
        network::fetch_peer_list(tracker_url, encoded_info_hash, peer_id, port,
                                 uploaded, downloaded, left, compact);

    Peer peer = peer_list[0];
    std::string peer_ip = peer.ip_addr;
    int peer_port = peer.port;

    std::string protocol = "BitTorrent protocol";
    CustomSocket client_socket(peer_ip, peer_port);

    if (client_socket.connect_to_server()) {

      HandshakeMessage handshake(info_hash, peer_id);
      client_socket.send_handshake_message(handshake.body);

      size_t responseSize = 68;
      std::vector<unsigned char> response =
          client_socket.receive_handshake_message(responseSize);

      size_t peerIdSize = 20;
      std::vector<unsigned char> peerId(response.end() - peerIdSize,
                                        response.end());

      std::string peerIdHexString = scrypt::bytes_to_hex_string(peerId);

      try {
        client_socket.download_file(torrent_metadata, output_file);
        std::cout << "Downloaded " << torrent_file << " to " << output_file
                  << std::endl;
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
  }

  return 0;
}
} // namespace bittu
