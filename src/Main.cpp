#include "headers/bittu.hpp"
#include <iostream>
#include <string>

int main(int argc, char *argv[]) {
  std::string command = argv[1];

  if (command == "decode") {
    return bittu::decode_command(argc, argv);
  } else if (command == "info") {
    return bittu::info_command(argc, argv);
  } else if (command == "peers") {
    return bittu::peers_command(argc, argv);
  } else if (command == "handshake") {
    return bittu::handshake_command(argc, argv);
  } else if (command == "download_piece") {
    return bittu::download_piece_command(argc, argv);
  } else if (command == "download") {
    return bittu::download(argc, argv);
  } else {
    std::cerr << "unknown command: " << command << std::endl;
    return 1;
  }

  return 0;
}
