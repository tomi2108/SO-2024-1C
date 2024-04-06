#include "connection.h"

void handshake_server(void) {}

void handshake_client(void) {}

int connection_create_client(char *server_ip, char *server_port) {
  int err;
  struct addrinfo hints;
  struct addrinfo *server_info;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  err = getaddrinfo(server_ip, server_port, &hints, &server_info);
  if (err != 0)
    return err;

  int fd_socket = socket(server_info->ai_family, server_info->ai_socktype,
                         server_info->ai_protocol);

  err = connect(fd_socket, server_info->ai_addr, server_info->ai_addrlen);
  if (err != 0)
    return err;

  freeaddrinfo(server_info);
  handshake_client();
  return fd_socket;
}

int connection_create_server(char *port) {

  int err;
  struct addrinfo hints;
  struct addrinfo *server_info;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  err = getaddrinfo(NULL, port, &hints, &server_info);
  if (err != 0)
    return err;

  int fd_escucha = socket(server_info->ai_family, server_info->ai_socktype,
                          server_info->ai_protocol);

  err = bind(fd_escucha, server_info->ai_addr, server_info->ai_addrlen);
  if (err != 0)
    return err;

  err = listen(fd_escucha, SOMAXCONN);
  if (err != 0)
    return err;

  handshake_server();
  freeaddrinfo(server_info);
  return fd_escucha;
}

int connection_accept_client(int fd_server_socket) {
  return accept(fd_server_socket, NULL, NULL);
}

int connection_close(int fd_socket) { return close(fd_socket); }
