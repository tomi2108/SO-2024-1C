#ifndef UTILS_CONNECTION_H_
#define UTILS_CONNECTION_H_

#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * @fn     connection_create_client
 * @param  server_ip   Ip addres of the server to connect to
 * @param  server_port Port where server is listening
 * @return Client socket file descriptor, -1 (and sets errno) if connection error happened
 * @brief  Opens a socket and connects to the server, the connection should be
 * closed with connection_close(1)
 */
int connection_create_client(char *server_ip, char *server_port);

/**
 * @fn      connection_create_server
 * @param   server_port Port where server will be listening
 * @return  Server listener socket file descriptor, -1 (and sets errno) if connection error happened
 * @brief   Creates a server connection for clients to connect with
 * connection_create_client
 */
int connection_create_server(char *server_port);

/**
 * @fn     connection_accept_client
 * @param  fd_sever_socket Socket file descriptor for server listener, returned
 * by connection_create_server
 * @return Socket file descriptor for the connected client or -1 if error ocurred and sets errno
 * @brief  Blocks until a client connects to the given socket
 */
int connection_accept_client(int fd_server_socket);

/**
 * @fn     connection_close
 * @param  fd_socket Socket file descriptor to be closed
 * @return 0 on succes, -1 otherwise and sets errno
 * @brief  Closes the given socket
 */
int connection_close(int fd_socket);

#endif
