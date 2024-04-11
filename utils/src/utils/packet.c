#include "packet.h"
#include "buffer.h"

packet_t *packet_create(packet_type type) {
  packet_t *packet = malloc(sizeof(packet_t));
  if (packet == NULL)
    return NULL;

  packet->type = type;
  packet->buffer = buffer_create();
  return packet;
}

void packet_destroy(packet_t *packet) {
  buffer_destroy(packet->buffer);
  free(packet);
}

int packet_add(packet_t *packet, void *data, size_t size) {
  return buffer_add(packet->buffer, data, size);
}

void packet_read(packet_t *packet, void *data, size_t size) {
  buffer_read(packet->buffer, data, size);
}

int packet_add_uint32(packet_t *packet, uint32_t data) {
  return buffer_add_uint32(packet->buffer, data);
}

int packet_add_uint8(packet_t *packet, uint8_t data) {
  return buffer_add_uint8(packet->buffer, data);
}

int packet_add_string(packet_t *packet, char *string) {
  uint32_t length = strlen(string);
  int err = buffer_add_uint32(packet->buffer, length);
  int err_string = buffer_add_string(packet->buffer, length, string);
  if ((err && err_string) == 0)
    return 0;
  else
    return -1;
}

uint32_t packet_read_uint32(packet_t *packet) {
  return buffer_read_uint32(packet->buffer);
}

uint8_t packet_read_uint8(packet_t *packet) {
  return buffer_read_uint8(packet->buffer);
}

char *packet_read_string(packet_t *packet, uint32_t *length) {
  *length = buffer_read_uint32(packet->buffer);
  return buffer_read_string(packet->buffer, *length);
}

int packet_send(packet_t *packet, int socket) {
  buffer_t *send_buffer = buffer_create();
  if (send_buffer == NULL)
    return -1;

  int err_type = buffer_add(send_buffer, &packet->type, sizeof(packet_type));
  if (err_type == -1)
    return -1;

  int err_size = buffer_add_uint32(send_buffer, packet->buffer->size);
  if (err_size == -1)
    return -1;

  int err_stream =
      buffer_add(send_buffer, packet->buffer->stream, packet->buffer->size);
  if (err_stream == -1)
    return -1;

  int err_send = send(socket, send_buffer->stream, send_buffer->size, 0);
  if (err_send == -1)
    return -1;

  buffer_destroy(send_buffer);
  return 0;
}

packet_t *packet_recieve(int socket) {
  packet_t *packet = packet_create(0);
  if (packet == NULL)
    return NULL;

  int err_type =
      recv(socket, &(packet->type), sizeof(packet_type), MSG_WAITALL);
  if (err_type == -1)
    return NULL;

  int err_size =
      recv(socket, &(packet->buffer->size), sizeof(uint32_t), MSG_WAITALL);
  if (err_size == -1)
    return NULL;

  packet->buffer->stream = malloc(packet->buffer->size);
  if (packet->buffer->stream == NULL)
    return NULL;

  int err_stream =
      recv(socket, packet->buffer->stream, packet->buffer->size, MSG_WAITALL);
  if (err_stream == -1)
    return NULL;
  return packet;
}

packet_t *packet_dup(packet_t *packet) {
  packet_t *duplicated = packet_create(0);
  if (duplicated == NULL)
    return NULL;

  duplicated->type = packet->type;
  duplicated->buffer = buffer_dup(packet->buffer);

  if (duplicated->buffer == NULL) {
    packet_destroy(duplicated);
    return NULL;
  }
  return duplicated;
};
