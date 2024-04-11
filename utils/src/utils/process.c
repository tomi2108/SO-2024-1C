#include "process.h"
#include "packet.h"

packet_t *process_pack(process_t process) {
  packet_t *packet = packet_create(PROCESS);

  packet_add_uint32(packet, process.pid);
  packet_add(packet, &process.status, sizeof(process_status));
  packet_add_string(packet, process.path);

  return packet;
}

process_t process_unpack(packet_t *packet) {
  process_t process;

  process.pid = packet_read_uint32(packet);
  packet_read(packet, &process.status, sizeof(process_status));
  process.path = packet_read_string(packet, NULL);

  return process;
}
