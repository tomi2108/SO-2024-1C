#ifndef UTILS_PROCESS_H_
#define UTILS_PROCESS_H_

#include "packet.h"

typedef enum {
  NEW,
  READY,
  EXEC,
  BLOCKED,
  FINISHED,
} process_status;

typedef struct {
  uint32_t pid;
  char *path;
  process_status status;
} process_t;

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
 * @brief Prints a process to sdout
 */
void process_print(process_t process);

/**
 * @fn     process_status_to_string
 * @param  status Status to transform
 * @return String representation of the process status
 * @brief  Transforms a process status to string
 */
char *process_status_to_string(process_status status);

#endif
