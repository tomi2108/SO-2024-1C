#include "status.h"
#include "packet.h"

status_code status_read_packet(packet_t *packet) {
  if (packet->type == STATUS) {
    return packet_read_uint8(packet);
  }
  return UNKNOWN_PACKET;
}

packet_t *status_create_packet(status_code status_code) {
  packet_t *packet = packet_create(STATUS);
  packet_add_uint8(packet, status_code);
  return packet;
}
