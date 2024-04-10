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

void packet_add(packet_t *packet, void *data, size_t size) {
  buffer_add(packet->buffer, data, size);
}

void packet_read(packet_t *packet, void *data, size_t size) {
  buffer_read(packet->buffer, data, size);
}

void packet_add_uint32(packet_t *packet, uint32_t data) {
  buffer_add_uint32(packet->buffer, data);
}

void packet_add_uint8(packet_t *packet, uint8_t data) {
  buffer_add_uint8(packet->buffer, data);
}

void packet_add_string(packet_t *packet, uint32_t length, char *string) {
  buffer_add_uint32(packet->buffer, length);
  buffer_add_string(packet->buffer, length, string);
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
void packet_send(packet_t *packet, int socket) {
  buffer_t *send_buffer = buffer_create();

  buffer_add(send_buffer, &packet->type, sizeof(packet_type));
  buffer_add_uint32(send_buffer, packet->buffer->size);
  buffer_add(send_buffer, packet->buffer->stream, packet->buffer->size);

  send(socket, send_buffer->stream, send_buffer->size, 0);
  buffer_destroy(send_buffer);
}

packet_t *packet_recieve(int socket) {
  packet_t *packet = packet_create(0);

  recv(socket, &(packet->type), sizeof(packet_type), MSG_WAITALL);
  recv(socket, &(packet->buffer->size), sizeof(uint32_t), MSG_WAITALL);

  packet->buffer->stream = malloc(packet->buffer->size);
  recv(socket, packet->buffer->stream, packet->buffer->size, MSG_WAITALL);

  return packet;
}

packet_t *packet_dup(packet_t *packet) {
  packet_t *duplicated = packet_create(0);

  duplicated->type = packet->type;
  duplicated->buffer = buffer_dup(packet->buffer);

  return duplicated;
};
