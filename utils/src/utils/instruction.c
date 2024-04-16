#include "instruction.h"
#include "commons/collections/list.h"
#include "packet.h"
#include <stdint.h>

packet_t *instruction_pack(instruction_t instruction) {
  packet_t *packet = packet_create(INSTRUCTION);
  if (packet == NULL)
    return NULL;

  int err_op = packet_add(packet, &instruction.op, sizeof(instruction_op_t));
  if (err_op == -1) {
    packet_destroy(packet);
    return NULL;
  }

  int err_params_size = packet_add_uint32(packet, list_size(instruction.params));
  if (err_params_size == -1) {
    packet_destroy(packet);
    return NULL;

  }

  t_list_iterator *iterator = list_iterator_create(instruction.params);
  while (list_iterator_has_next(iterator)) {
    // Todos los parametros de instrucciones son numeros?? si no es asi, como
    // podemos representarlos... ?
    uint32_t *next = list_iterator_next(iterator);
    int err_param = packet_add_uint32(packet, *next);
    if(err_param == -1){
      packet_destroy(packet);
      return NULL;
    }
  }

  return packet;
}

instruction_t instruction_unpack(packet_t *packet) {
  instruction_t instruction;
  packet_read(packet, &instruction.op, sizeof(instruction_op_t));
  uint32_t list_size = packet_read_uint32(packet);

  instruction.params = list_create();
  for (int i = 0; i < list_size; i++) {
    uint32_t param = packet_read_uint32(packet);
    list_add(instruction.params, &param);
  }

  return instruction;
}
