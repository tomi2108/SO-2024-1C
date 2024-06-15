#include "process.h"
#include "packet.h"

process_t *process_create(uint32_t pid, char *path, uint32_t quantum) {
  process_t *process = malloc(sizeof(process_t));
  process->pid = pid;
  process->path = path;
  process->io_packet = NULL;
  process->quantum = quantum;

  process->program_counter = 0;
  process->registers.ax = 0;
  process->registers.bx = 0;
  process->registers.cx = 0;
  process->registers.dx = 0;
  process->registers.eax = 0;
  process->registers.ebx = 0;
  process->registers.ecx = 0;
  process->registers.edx = 0;
  process->registers.si = 0;
  process->registers.di = 0;
  return process;
}

void process_destroy(process_t *process) {
  free(process->path);
  free(process);
}

packet_t *process_pack(process_t process) {
  packet_t *packet = packet_create(PROCESS);

  packet_add_uint32(packet, process.pid);
  packet_add_string(packet, process.path);
  packet_add_uint32(packet, process.program_counter);
  packet_add_uint32(packet, process.quantum);

  packet_add_uint8(packet, process.registers.ax);
  packet_add_uint8(packet, process.registers.bx);
  packet_add_uint8(packet, process.registers.cx);
  packet_add_uint8(packet, process.registers.dx);
  packet_add_uint32(packet, process.registers.eax);
  packet_add_uint32(packet, process.registers.ebx);
  packet_add_uint32(packet, process.registers.ecx);
  packet_add_uint32(packet, process.registers.edx);
  packet_add_uint32(packet, process.registers.di);
  packet_add_uint32(packet, process.registers.si);
  return packet;
}

process_t process_unpack(packet_t *packet) {
  process_t process;

  process.pid = packet_read_uint32(packet);
  process.path = packet_read_string(packet);
  process.program_counter = packet_read_uint32(packet);
  process.quantum = packet_read_uint32(packet);
  process.io_packet = NULL;

  process.registers.ax = packet_read_uint8(packet);
  process.registers.bx = packet_read_uint8(packet);
  process.registers.cx = packet_read_uint8(packet);
  process.registers.dx = packet_read_uint8(packet);
  process.registers.eax = packet_read_uint32(packet);
  process.registers.ebx = packet_read_uint32(packet);
  process.registers.ecx = packet_read_uint32(packet);
  process.registers.edx = packet_read_uint32(packet);
  process.registers.si = packet_read_uint32(packet);
  process.registers.di = packet_read_uint32(packet);
  return process;
}

void process_print(process_t process, char *status) {
  printf("[%s] Pid:%u Instrucciones:%s \n", status, process.pid, process.path);
}

process_t *process_dup(process_t p_to_dup) {
  process_t *process = malloc(sizeof(process_t));

  process->program_counter = p_to_dup.program_counter;
  process->pid = p_to_dup.pid;
  process->path = strdup(p_to_dup.path);
  process->quantum = p_to_dup.quantum;
  if (p_to_dup.io_packet != NULL)
    process->io_packet = packet_dup(p_to_dup.io_packet);

  process->registers.ax = p_to_dup.registers.ax;
  process->registers.bx = p_to_dup.registers.bx;
  process->registers.cx = p_to_dup.registers.cx;
  process->registers.dx = p_to_dup.registers.dx;
  process->registers.eax = p_to_dup.registers.eax;
  process->registers.ebx = p_to_dup.registers.ebx;
  process->registers.ecx = p_to_dup.registers.ecx;
  process->registers.edx = p_to_dup.registers.edx;
  process->registers.si = p_to_dup.registers.si;
  process->registers.di = p_to_dup.registers.di;

  return process;
}
