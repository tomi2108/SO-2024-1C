#include "connection.h"

int handshake_server(void) {}

int handshake_client(void) {}

int connection_create_client(char *server_ip, char *server_port) {
  struct addrinfo hints;
  struct addrinfo *server_info;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  int err_get_addr = getaddrinfo(server_ip, server_port, &hints, &server_info);
  if (err_get_addr != 0)
    return -1;

  int fd_socket = socket(server_info->ai_family, server_info->ai_socktype,
                         server_info->ai_protocol);

  if (fd_socket == -1)
    return -1;

  int err_connect =
      connect(fd_socket, server_info->ai_addr, server_info->ai_addrlen);
  if (err_connect == -1)
    return -1;

  freeaddrinfo(server_info);
  int err_handshake = handshake_client();
  if (err_handshake == -1)
    return -1;

  return fd_socket;
}

int connection_create_server(char *port) {

  struct addrinfo hints;
  struct addrinfo *server_info;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  int err_get_addr = getaddrinfo(NULL, port, &hints, &server_info);
  if (err_get_addr != 0)
    return -1;

  int fd_socket = socket(server_info->ai_family, server_info->ai_socktype,
                         server_info->ai_protocol);
  if (fd_socket == -1)
    return -1;

  int err_bind = bind(fd_socket, server_info->ai_addr, server_info->ai_addrlen);
  if (err_bind == -1)
    return -1;

  int err_listen = listen(fd_socket, SOMAXCONN);
  if (err_listen == -1)
    return -1;

  freeaddrinfo(server_info);

  int err_handshake = handshake_server();
  if (err_handshake == -1)
    return -1;

  return fd_socket;
}

int connection_accept_client(int fd_server_socket) {
  return accept(fd_server_socket, NULL, NULL);
}

int connection_close(int fd_socket) { return close(fd_socket); }
