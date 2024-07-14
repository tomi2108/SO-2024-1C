#ifndef UTILS_PACKET_H_
#define UTILS_PACKET_H_

#include "buffer.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

typedef enum {
  HANDSHAKE,
  STATUS,
  READ_DIR,
  WRITE_DIR,
  INIT_PROCESS,
  FETCH_INSTRUCTION,
  INSTRUCTION,
  REGISTER_IO,
  UNREGISTER_IO,
  PROCESS,
  INTERRUPT,
  RESIZE_PROCESS,
  MEMORY_CONTENT,
  OUT_OF_MEMORY,
  FREE_PROCESS,
  FETCH_FRAME_NUMBER,
  RESPONSE_FRAME_NUMBER,
  TAMANIO_PAGINA_REQUEST,
  TAMANIO_PAGINA_RESPONSE,
  PRINT_TLB_PACKET,
} packet_type;

typedef struct {
  packet_type type;
  buffer_t *buffer;
} packet_t;

/**
 * @fn     packet_create
 * @param  type Type of packet
 * @return The packet created or NULL if error ocurred
 * @brief  Creates a packet without a type and with an empty buffer
 */
packet_t *packet_create(packet_type type);

/**
 * @fn     packet_destroy
 * @param  packet The packet to destroy
 * @brief  Destroys the given packet, freeing all memory
 */
void packet_destroy(packet_t *packet);

/**
 * @fn     packet_add
 * @param  packet Packet to add to
 * @param  data   Data to add to the packet's buffer
 * @param  size   Size of the data in bytes
 * @return 0 if adding was successful or -1 if error ocurred
 * @brief  Adds the given data to the end of the packet's buffer
 */
int packet_add(packet_t *packet, void *data, size_t size);

/**
 * @fn    packet_read
 * @param packet Packet to read from
 * @param data   Stream to read to
 * @param size   Size in bytes to write to the data stream from the packet
 * @brief Reads from packets's buffer into data stream
 */
void packet_read(packet_t *packet, void *data, size_t size);

/**
 * @fn     packet_add_uint32
 * @param  packet Packet to add to
 * @param  data   Data to add to the packet's buffer
 * @return 0 if adding was successful or -1 if error ocurred
 * @brief  Adds the given data to the end of the packet's buffer
 */
int packet_add_uint32(packet_t *packet, uint32_t data);

/**
 * @fn     packet_add_uint8
 * @param  packet Packet to add to
 * @param  data   Data to add to the packet's buffer
 * @return 0 if adding was successful or -1 if error ocurred
 * @brief  Adds the given data to the end of the packet's buffer
 */
int packet_add_uint8(packet_t *packet, uint8_t data);

/**
 * @fn     packet_add_string
 * @param  packet Packet to add to
 * @param  length Length of the string to add
 * @param  string String to add to the end of the packet's buffer
 * @return 0 if adding was successful or -1 if error ocurred
 * @brief  Adds the given data to the end of the packet's buffer
 */
int packet_add_string(packet_t *packet, char *string);

/*
 * @fn    packet_read_uint32
 * @param packet Packet to read from
 * @return Read data
 * @brief Reads from packets's buffer
 */
uint32_t packet_read_uint32(packet_t *packet);

/*
 * @fn    packet_read_uint8
 * @param packet Packet to read from
 * @return Read data
 * @brief Reads from packets's buffer
 */
uint8_t packet_read_uint8(packet_t *packet);

/*
 * @fn    packet_read_string
 * @param packet Packet to read from
 * @return Read string
 * @brief Reads from packets's buffer
 */
char *packet_read_string(packet_t *packet);

/**
 * @fn     packet_send
 * @param  packet Packet to send
 * @param  socket Socket file descriptor to send the packet
 * @return 0 if sending was successful or -1 if error ocurred
 * @brief  sends the packet to the given socket
 */
int packet_send(packet_t *packet, int socket);

/**
 * @fn     packet_recieve
 * @param  socket Socket file descriptor to recieve the packet
 * @return Recieved packet or NULL if error ocurred
 * @brief  Blocks until socket recieves a packet and then stores it in packet
 * pointer which must be destroyed with packet_destroy(1)
 */
packet_t *packet_recieve(int socket);

/**
 * @fn     packet_dup
 * @param  packet Packet to duplicate
 * @return A new packet that must be destroyed with packet_destroy(1) or NULL if
 * error ocurred
 * @brief  Creates a new packet duplicated from the given packet.
 */
packet_t *packet_dup(packet_t *packet);

#endif
