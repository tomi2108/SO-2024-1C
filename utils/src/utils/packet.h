#ifndef UTILS_PACKET_H_
#define UTILS_PACKET_H_

#include "buffer.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

typedef enum { INSTRUCTION } packet_type;
typedef enum { KERNEL = 1, CPU = 2, IO = 3, MEMORY = 4 } packet_author;
typedef struct {
  packet_type type;
  buffer_t *buffer;
  packet_author author;
} packet_t;

/**
 * @fn     packet_create
 * @param  author Author of the packet
 * @return The packet created
 * @brief  Creates a packet without a type and with an empty buffer
 */
packet_t *packet_create(packet_author author);

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
 * @brief  Adds the given data to the end of the packet's buffer
 */
void packet_add(packet_t *packet, void *data, size_t size);

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
 * @brief  Adds the given data to the end of the packet's buffer
 */
void packet_add_uint32(packet_t *packet, uint32_t data);

/**
 * @fn     packet_add_uint8
 * @param  packet Packet to add to
 * @param  data   Data to add to the packet's buffer
 * @brief  Adds the given data to the end of the packet's buffer
 */
void packet_add_uint8(packet_t *packet, uint8_t data);

/**
 * @fn     packet_add_string
 * @param  packet Packet to add to
 * @param  length Length of the string to add
 * @param  string String to add to the end of the packet's buffer
 * @brief  Adds the given string to the end of the packet's buffer
 */
void packet_add_string(packet_t *packet, uint32_t length, char *string);

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
 * @param length Pointer to write the length of the read string
 * @return Read string
 * @brief Reads from packets's buffer
 */
char *packet_read_string(packet_t *packet, uint32_t *length);

/**
 * @fn     packet_send
 * @param  packet Packet to send
 * @param  socket Socket file descriptor to send the packet
 * @brief  sends the packet to the given socket
 */
void packet_send(packet_t *packet, int socket);

/**
 * @fn     packet_recieve
 * @param  packet Packet to store the recieved packet
 * @parma  socket Socket file descriptor to recieve the packet
 * @return Recieved packet type or -1 if packet is not empty
 * @brief  Blocks until socket recieves a packet and then stores it in packet
 * pointer
 */
packet_type packet_recieve(packet_t *packet, int socket);

/**
 * @fn     packet_dup
 * @param  packet Packet to duplicate
 * @return A new packet that must be destroyed with packet_destroy(1)
 * @brief  Creates a new packet duplicated from the given packet.
 */
packet_t *packet_dup(packet_t *packet);
#endif
