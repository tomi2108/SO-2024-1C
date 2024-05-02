#ifndef UTILS_PROCESS_H_
#define UTILS_PROCESS_H_

#include "packet.h"

typedef struct {
  uint8_t ax;
  uint8_t bx;
  uint8_t cx;
  uint8_t dx;
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
} process_registers;

typedef struct {
  uint32_t pid;
  char *path;
  uint32_t quantum;
  uint32_t program_counter;
  process_registers registers;
} process_t;

/**
 * @fn     process_create
 * @param  pid     Process id
 * @param  path    Instruction path
 * @param  quantum Initial quantum
 * @return Created process
 * @brief  Creates a process with the given parameters
 */
process_t *process_create(uint32_t pid, char *path, uint32_t quantum);

/**
 * @fn    process_destroy
 * @param process Process to destroy
 * @brief Destroys the process created with process_create(3)
 */
void process_destroy(process_t *process);

/**
 * @fn     process_pack
 * @param  process Process to pack
 * @return A pointer to the created packet that must be destroyed with
 * packet_destroy(1)
 * @brief  Packs a process inside a packet
 */
packet_t *process_pack(process_t process);

/**
 * @fn     process_unpack
 * @param  packet Packet to unpack from
 * @return Process unpacked from packet
 * @brief  Unpacks a process from a packet packed with process_pack(1)
 */
process_t process_unpack(packet_t *packet);

/**
 * @fn    process_print
 * @param process Process to print
 * @param status  Process Status
 * @brief Prints a process to sdout
 */
void process_print(process_t process, char *status);

/**
 * @fn    process_dup
 * @param process Process to duplicate
 * @return A process created with process_create, duplicated from the given
 * process
 * @brief Duplicates a process
 */
process_t *process_dup(process_t process);

#endif
