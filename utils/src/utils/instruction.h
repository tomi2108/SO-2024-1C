#ifndef UTILS_INSTRUCTION_H_
#define UTILS_INSTRUCTION_H_

#include "packet.h"
#include <commons/collections/list.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef enum { SET, SUB, SUM, JNZ, IO_GEN_SLEEP } instruction_op_t;

typedef struct {
  instruction_op_t op;
  t_list *params;
} instruction_t;

/**
 * @fn     instruction_pack
 * @param  packet Packet where the instruction will be packed, created with
 * packet_create(1)
 * @param  instruction Instruction to pack
 * @return Modified packet
 * @brief  Packs an instruction inside a packet ready to be sent with
 * packet_send(2)
 */
packet_t *instruction_pack(packet_t *packet, instruction_t instruction);

/**
 * @fn     instruction_unpack
 * @param  packet Packet containing the instruction packed with person_pack(2)
 * @return Instruction struct created from the packet
 * @brief  Unpacks an instruction from a packet packed with person_pack(2)
 */
instruction_t instruction_unpack(packet_t *packet);

#endif
