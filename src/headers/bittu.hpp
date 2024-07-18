#pragma once

namespace bittu {
int decode_command(int argc, char *argv[]);
int info_command(int argc, char *argv[]);
int peers_command(int argc, char *argv[]);
int handshake_command(int argc, char *argv[]);
int download_piece_command(int argc, char *argv[]);
int download(int argc, char *argv[]);
} // namespace bittu
