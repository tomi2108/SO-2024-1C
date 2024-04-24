#include "instruction.h"
#include "packet.h"
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
  *(uint32_t *)first_param->value = *(long *)second_param->value;
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
    *pc = *(long *)second_param->value;
  }
}

void instruction_io_gen_sleep(t_list *params, int socket) {
  param *first_param = list_get(params, 0);
  param *second_param = list_get(params, 1);
  packet_t *req = packet_create(BLOCKING_OP);
  packet_add_uint32(req, IO_GEN_SLEEP);
  packet_add_string(req, (char *)first_param->value);

  packet_add(req, second_param->value, sizeof(long));
  packet_send(req, socket);

  packet_destroy(req);
}

uint8_t instruction_mov_in(t_list *params, int client_socket,
                           uint32_t physical_addres) {
  param *first_param = list_get(params, 0);

  packet_t *req = packet_create(READ_DIR);
  packet_add_uint32(req, physical_addres);
  packet_send(req, client_socket);
  packet_destroy(req);

  packet_t *res = packet_recieve(client_socket);
  uint8_t memory_content = packet_read_uint8(res);
  *(uint32_t *)first_param->value = memory_content;
  packet_destroy(res);
  return memory_content;
}

void instruction_mov_out(t_list *params, int client_socket,
                         uint32_t physical_addres) {
  param *second_param = list_get(params, 1);

  packet_t *req = packet_create(WRITE_DIR);
  param_type p = NUMBER;
  packet_add_uint32(req, physical_addres);
  packet_add(req, &p, sizeof(param_type));
  packet_add_uint32(req, *(uint32_t *)second_param->value);
  packet_send(req, client_socket);
  packet_destroy(req);

  packet_t *res = packet_recieve(client_socket);
  status_code memory_status = packet_read_uint32(res);
  packet_destroy(res);
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

void instruction_io_stdin(t_list *params, int socket,
                          uint32_t (*translate_addres)(uint32_t)) {

  param *first_param = list_get(params, 0);
  param *second_param = list_get(params, 1);
  param *third_param = list_get(params, 2);

  packet_t *req = packet_create(BLOCKING_OP);
  packet_add_uint32(req, IO_STDIN_READ);
  packet_add_string(req, (char *)first_param->value);

  packet_add_uint32(req, translate_addres(*(uint32_t *)second_param->value));
  packet_add_uint32(req, *(uint32_t *)third_param->value);
  packet_send(req, socket);

  packet_destroy(req);
}

void instruction_io_stdout(t_list *params, int socket,
                           uint32_t (*translate_addres)(uint32_t)) {

  param *first_param = list_get(params, 0);
  param *second_param = list_get(params, 1);
  param *third_param = list_get(params, 2);

  packet_t *req = packet_create(BLOCKING_OP);
  packet_add_uint32(req, IO_STDOUT_WRITE);
  packet_add_string(req, (char *)first_param->value);

  packet_add_uint32(req, translate_addres(*(uint32_t *)second_param->value));
  packet_add_uint32(req, *(uint32_t *)third_param->value);

  packet_send(req, socket);
  packet_destroy(req);
}
