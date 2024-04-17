#include "connection.h"
#include "packet.h"
#include "status.h"

int handshake_server(packet_t *handshake_packet) {
  char *handshake_string = packet_read_string(handshake_packet);
  if (strcmp("AGUANTE_MESSI", handshake_string) == 0)
    return 0;
  return -1;
}

int handshake_client(int socket) {
  packet_t *packet = packet_create(HANDSHAKE);
  packet_add_string(packet, "AGUANTE_MESSI");
  packet_send(packet, socket);
  packet_destroy(packet);

  packet_t *res = packet_recieve(socket);
  status_code res_status = status_read_packet(res);
  packet_destroy(res);

  if (res_status == OK)
    return 0;
  return -1;
}

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
  handshake_client(fd_socket);

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

  return fd_socket;
}

int connection_accept_client(int fd_server_socket) {
  int client_socket = accept(fd_server_socket, NULL, NULL);
  packet_t *handshake_packet = packet_recieve(client_socket);

  int handshake_result = handshake_server(handshake_packet);
  packet_destroy(handshake_packet);
  if (handshake_result == -1) {
    packet_t *result = status_create_packet(ERROR);
    packet_send(result, client_socket);
    packet_destroy(result);
    connection_close(client_socket);
    return -1;
  }

  packet_t *result = status_create_packet(OK);
  packet_send(result, client_socket);
  packet_destroy(result);
  return client_socket;
}

int connection_close(int fd_socket) { return close(fd_socket); }
