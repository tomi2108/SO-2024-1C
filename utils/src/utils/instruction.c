#include "instruction.h"
#include <stdint.h>

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
  case MOV_IN:
    return "MOV_IN";
  case MOV_OUT:
    return "MOV_OUT";
  case RESIZE:
    return "RESIZE";
  case COPY_STRING:
    return "COPY_STRING";
  case IO_STDIN_READ:
    return "IO_STDIN_READ";
  case IO_STDOUT_WRITE:
    return "IO_STDOUT_WRITE";
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
  if (strcmp(op, "MOV_IN") == 0)
    return MOV_IN;
  if (strcmp(op, "MOV_OUT") == 0)
    return MOV_OUT;
  if (strcmp(op, "RESIZE") == 0)
    return RESIZE;
  if (strcmp(op, "COPY_STRING") == 0)
    return COPY_STRING;
  if (strcmp(op, "IO_STDOUT_WRITE") == 0)
    return IO_STDOUT_WRITE;
  if (strcmp(op, "IO_STDIN_READ") == 0)
    return IO_STDIN_READ;
  return UNKNOWN_INSTRUCTION;
}

int instruction_is_blocking(instruction_op op) {
  if (op == IO_GEN_SLEEP || op == IO_STDIN_READ || op == IO_STDOUT_WRITE)
    return 1;

  return 0;
}

void instruction_set(t_list *params) {
  param *first_param = list_get(params, 0);
  param *second_param = list_get(params, 1);
  *(uint32_t *)first_param->value = *(uint32_t *)second_param->value;
}

void instruction_sum(t_list *params) {
  param *first_param = list_get(params, 0);
  param *second_param = list_get(params, 1);

  *(uint32_t *)first_param->value =
      *(uint32_t *)first_param->value + *(uint32_t *)second_param->value;
}

void instruction_sub(t_list *params) {
  param *first_param = list_get(params, 0);
  param *second_param = list_get(params, 1);

  *(uint32_t *)first_param->value =
      *(uint32_t *)first_param->value - *(uint32_t *)second_param->value;
}

void instruction_jnz(t_list *params, uint32_t *pc) {
  param *first_param = list_get(params, 0);
  param *second_param = list_get(params, 1);

  if (*(uint32_t *)first_param->value != 0) {
    *pc = *(uint32_t *)second_param->value;
  }
}

void instruction_io_gen_sleep(t_list *params, packet_t *instruction_packet) {
  param *first_param = list_get(params, 0);
  param *second_param = list_get(params, 1);

  packet_add_string(instruction_packet, (char *)first_param->value);
  packet_add_uint32(instruction_packet, *(uint32_t *)second_param->value);
}

void instruction_mov_in(t_list *params, int client_socket, t_log *logger,
                        uint32_t (*translate_address)(uint32_t), uint32_t pid) {
  param *first_param = list_get(params, 0);
  param *second_param = (param *)list_get(params, 1);

  uint32_t logical_address = *(uint32_t *)second_param->value;
  uint32_t physical_address = translate_address(logical_address);

  packet_t *req = packet_create(READ_DIR);
  packet_add_uint32(req, physical_address);
  packet_add_uint32(req, pid);
  packet_add_uint32(req, 4);

  packet_send(req, client_socket);
  packet_destroy(req);

  packet_t *res = packet_recieve(client_socket);

  for (int i = 0; i < 4; i++) {
    uint8_t byte = packet_read_uint8(res);
    *((uint8_t *)first_param->value + i) = byte;
  }

  log_info(logger,
           "PID: %u - Accion: LECTURA - Direccion fisica: %u - Valor: %u", pid,
           physical_address, *(uint32_t *)first_param->value);
  packet_destroy(res);
}

void instruction_mov_out(t_list *params, int client_socket, t_log *logger,
                         uint32_t (*translate_address)(uint32_t),
                         uint32_t pid) {

  param *first_param = list_get(params, 0);
  param *second_param = list_get(params, 1);

  uint32_t logical_address = *(uint32_t *)first_param->value;
  uint32_t physical_address = translate_address(logical_address);

  uint32_t write_value = *(uint32_t *)second_param->value;
  packet_t *req = packet_create(WRITE_DIR);
  packet_add_uint32(req, physical_address);
  packet_add_uint32(req, pid);
  packet_add_uint32(req, 4);

  for (int i = 0; i < 4; i++)
    packet_add_uint8(req, *((uint8_t *)second_param->value + i));

  log_info(logger,
           "PID: %u - Accion: ESCRITURA - Direccion fisica: %u - Valor: %u",
           pid, physical_address, write_value);
  packet_send(req, client_socket);
  packet_destroy(req);
}

int instruction_resize(t_list *params, int client_socket, uint32_t pid) {

  param *first_param = list_get(params, 0);

  packet_t *req = packet_create(RESIZE_PROCESS);
  packet_add_uint32(req, pid);
  packet_add_uint32(req, *(uint32_t *)first_param->value);
  packet_send(req, client_socket);
  packet_destroy(req);

  packet_t *res = packet_recieve(client_socket);
  status_code status = status_unpack(res);
  if (status == OK)
    return 0;
  return -1;
}

void instruction_copy_string(t_list *params, uint32_t *si, uint32_t *di) {
  param *first_param = list_get(params, 0);
}

void instruction_io_stdin(t_list *params, packet_t *instruction_packet,
                          uint32_t (*translate_addres)(uint32_t),
                          uint32_t pid) {

  param *first_param = list_get(params, 0);
  param *second_param = list_get(params, 1);
  param *third_param = list_get(params, 2);

  packet_add_string(instruction_packet, (char *)first_param->value);

  packet_add_uint32(instruction_packet,
                    translate_addres(*(uint32_t *)second_param->value));
  packet_add_uint32(instruction_packet, pid);
  packet_add_uint32(instruction_packet, *(uint32_t *)third_param->value);
}

void instruction_io_stdout(t_list *params, packet_t *instruction_packet,
                           uint32_t (*translate_addres)(uint32_t),
                           uint32_t pid) {

  param *first_param = list_get(params, 0);
  param *second_param = list_get(params, 1);
  param *third_param = list_get(params, 2);

  packet_add_string(instruction_packet, (char *)first_param->value);

  packet_add_uint32(instruction_packet,
                    translate_addres(*(uint32_t *)second_param->value));
  packet_add_uint32(instruction_packet, pid);
  packet_add_uint32(instruction_packet, *(uint32_t *)third_param->value);
}
