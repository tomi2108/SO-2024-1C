#include "instruction.h"
#include "packet.h"

char *instruction_op_to_string(instruction_op op) {
  switch (op) {
  case SET:
    return "SET";
  case SUM:
    return "SUM";
  case SUB:
    return "SUB";
  case JNZ:
    return "JNZ";
  case IO_GEN_SLEEP:
    return "IO_GEN_SLEEP";
  default:
    return "UNKNOW_INSTRUCTION";
  };
}

instruction_op instruction_op_from_string(char *op) {

  if (strcmp(op, "SET") == 0)
    return SET;
  if (strcmp(op, "SUM") == 0)
    return SUM;
  if (strcmp(op, "SUB") == 0)
    return SUB;
  if (strcmp(op, "JNZ") == 0)
    return JNZ;
  if (strcmp(op, "IO_GEN_SLEEP") == 0)
    return IO_GEN_SLEEP;
  return UNKNOWN_INSTRUCTION;
}

int instruction_is_blocking(instruction_op op) {

  if (op == IO_GEN_SLEEP)
    return 1;

  return 0;
}

void instruction_set(t_list *params) {
  param *first_param = list_get(params, 0);
  param *second_param = list_get(params, 1);
  if (first_param->type == REGISTER) {
    *(uint8_t *)first_param->value = *(long *)second_param->value;
  }
  *(uint32_t *)first_param->value = *(long *)second_param->value;
}

void instruction_sum(t_list *params) {
  param *first_param = list_get(params, 0);
  param *second_param = list_get(params, 1);

  if (first_param->type == REGISTER) {
    if (second_param->type == REGISTER) {
      *(uint8_t *)first_param->value =
          *(uint8_t *)first_param->value + *(uint8_t *)second_param->value;
      return;
    }
    *(uint8_t *)first_param->value =
        *(uint8_t *)first_param->value + *(uint32_t *)second_param->value;
    return;
  }

  if (second_param->type == REGISTER) {
    *(uint32_t *)first_param->value =
        *(uint32_t *)first_param->value + *(uint8_t *)second_param->value;
    return;
  }
  *(uint32_t *)first_param->value =
      *(uint32_t *)first_param->value + *(uint32_t *)second_param->value;
  return;
}

void instruction_sub(t_list *params) {

  param *first_param = list_get(params, 0);
  param *second_param = list_get(params, 1);

  if (first_param->type == REGISTER) {
    if (second_param->type == REGISTER) {
      *(uint8_t *)first_param->value =
          *(uint8_t *)first_param->value - *(uint8_t *)second_param->value;
      return;
    }
    *(uint8_t *)first_param->value =
        *(uint8_t *)first_param->value - *(uint32_t *)second_param->value;
    return;
  }

  if (second_param->type == REGISTER) {
    *(uint32_t *)first_param->value =
        *(uint32_t *)first_param->value - *(uint8_t *)second_param->value;
    return;
  }
  *(uint32_t *)first_param->value =
      *(uint32_t *)first_param->value - *(uint32_t *)second_param->value;
  return;
}

void instruction_jnz(t_list *params, uint32_t *pc) {
  param *first_param = list_get(params, 0);
  param *second_param = list_get(params, 1);

  if (first_param->type == REGISTER) {
    if (*(uint8_t *)first_param->value != 0) {
      *pc = *(long *)second_param->value;
    }
  }
  if (*(uint32_t *)first_param->value != 0) {
    *pc = *(long *)second_param->value;
  }
}

void instruction_io_gen_sleep(t_list *params, int socket) {

  param *first_param = list_get(params, 0);
  param *second_param = list_get(params, 1);

  packet_t *res = packet_create(BLOCKING_OP);
  packet_add_string(res, (char *)first_param->value);
  packet_add(res, second_param->value, sizeof(long));
  packet_send(res, socket);
  packet_destroy(res);
}
