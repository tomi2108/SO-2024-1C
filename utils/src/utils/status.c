#include "status.h"
#include "packet.h"

status_code status_unpack(packet_t *packet) {
  if (packet->type == STATUS) {
    return packet_read_uint8(packet);
  }
  return UNKNOWN_PACKET;
}

packet_t *status_pack(status_code status_code) {
  packet_t *packet = packet_create(STATUS);
  if (packet == NULL)
    return NULL;

  int err = packet_add_uint8(packet, status_code);
  if (err) {
    packet_destroy(packet);
    return NULL;
  }
  return packet;
}
