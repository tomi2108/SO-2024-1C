#include "process.h"
#include "packet.h"

process_t *process_create(uint32_t pid, char *path, uint32_t quantum) {
  process_t *process = malloc(sizeof(process_t));
  process->program_counter = 0;
  process->pid = pid;
  process->path = path;
  process->status = NEW;
  process->quantum = quantum;
  return process;
}

void process_destroy(process_t *process) {
  free(process->path);
  free(process);
}

packet_t *process_pack(process_t process) {
  packet_t *packet = packet_create(PROCESS);

  packet_add_uint32(packet, process.pid);
  packet_add(packet, &process.status, sizeof(process_status));
  packet_add_string(packet, process.path);
  packet_add_uint32(packet, process.program_counter);
  packet_add_uint32(packet, process.quantum);

  return packet;
}

process_t process_unpack(packet_t *packet) {
  process_t process;

  process.pid = packet_read_uint32(packet);
  packet_read(packet, &process.status, sizeof(process_status));
  process.path = packet_read_string(packet);
  process.program_counter = packet_read_uint32(packet);
  process.quantum = packet_read_uint32(packet);
  return process;
}

void process_print(process_t process) {
  printf("Pid:%u Status:%s Path de instrucciones:%s\n", process.pid,
         process_status_to_string(process.status), process.path);
}

char *process_status_to_string(process_status status) {
  switch (status) {
  case NEW:
    return "NEW";
  case READY:
    return "READY";
  case BLOCKED:
    return "BLOCKED";
  case FINISHED:
    return "FINISHED";
  case EXEC:
    return "EXEC";
  default:
    return "UNKNOWN";
  }
}
