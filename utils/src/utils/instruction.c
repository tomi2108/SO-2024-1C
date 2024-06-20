#include "instruction.h"
#include "buffer.h"
#include "io_type.h"
#include "packet.h"

int ceil_div(uint32_t num, int denom) { return (num + denom - 1) / denom; }

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
  case IO_FS_CREATE:
    return "IO_FS_CREATE";
  case WAIT:
    return "WAIT";
  case SIGNAL:
    return "SIGNAL";
  case EXIT:
    return "EXIT";
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
  if (strcmp(op, "IO_FS_CREATE") == 0)
    return IO_FS_CREATE;
  if (strcmp(op, "WAIT") == 0)
    return WAIT;
  if (strcmp(op, "SIGNAL") == 0)
    return SIGNAL;
  if (strcmp(op, "EXIT") == 0)
    return EXIT;
  return UNKNOWN_INSTRUCTION;
}

int instruction_is_io(instruction_op op) {
  if (io_type_gen_is_compatible(op) || io_type_stdin_is_compatible(op) ||
      io_type_dialfs_is_compatible(op) || io_type_stdout_is_compatible(op))
    return 1;
  return 0;
}

int instruction_is_syscall(instruction_op op) {
  if (instruction_is_io(op) || op == RESIZE || op == WAIT || op == SIGNAL ||
      op == EXIT)
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

status_code instruction_mov_in(t_list *params, t_log *logger,
                               uint32_t (*translate_address)(uint32_t, uint32_t,
                                                             status_code *),
                               uint32_t pid, uint32_t page_size,
                               char *server_ip, char *server_port) {
  param *first_param = list_get(params, 0);
  param *second_param = list_get(params, 1);

  uint32_t logical_address = *(uint32_t *)second_param->value;
  status_code res_translate = OK;
  uint32_t physical_address =
      translate_address(logical_address, pid, &res_translate);
  if (res_translate == ERROR)
    return ERROR;

  buffer_t *read_buffer = buffer_create();

  uint32_t size = first_param->type == EXTENDED_REGISTER ? 4 : 1;

  uint32_t page_number = logical_address / page_size;
  uint32_t offset = logical_address - page_number * page_size;
  int remaining = size + offset - page_size;
  uint32_t split = size;
  if (remaining > 0)
    split = size - remaining;

  int client_socket = connection_create_client(server_ip, server_port);
  packet_t *req = packet_create(READ_DIR);
  packet_add_uint32(req, physical_address);
  packet_add_uint32(req, pid);
  packet_add_uint32(req, split);
  packet_send(req, client_socket);
  packet_destroy(req);
  packet_t *res = packet_recieve(client_socket);
  for (int i = 0; i < split; i++) {
    uint8_t byte = packet_read_uint8(res);
    log_info(logger,
             "PID: %u - Accion: LECTURA - Direccion fisica: %u - Valor: %u",
             pid, physical_address + i, byte);
    buffer_add_uint8(read_buffer, byte);
  }
  packet_destroy(res);
  connection_close(client_socket);

  while (remaining > 0) {
    size = remaining;
    logical_address += split;

    res_translate = OK;
    physical_address = translate_address(logical_address, pid, &res_translate);
    if (res_translate == ERROR) {
      buffer_destroy(read_buffer);
      return ERROR;
    }

    page_number = logical_address / page_size;
    offset = logical_address - page_number * page_size;
    remaining = size + offset - page_size;
    split = size;
    if (remaining > 0)
      split = size - remaining;

    client_socket = connection_create_client(server_ip, server_port);
    req = packet_create(READ_DIR);
    packet_add_uint32(req, physical_address);
    packet_add_uint32(req, pid);
    packet_add_uint32(req, split);
    packet_send(req, client_socket);
    packet_destroy(req);
    res = packet_recieve(client_socket);
    for (int i = 0; i < split; i++) {
      uint8_t byte = packet_read_uint8(res);
      log_info(logger,
               "PID: %u - Accion: LECTURA - Direccion fisica: %u - Valor: %u",
               pid, physical_address + i, byte);
      buffer_add_uint8(read_buffer, byte);
    }
    packet_destroy(res);
    connection_close(client_socket);
  }

  for (int i = 0; i < read_buffer->size; i++) {
    uint8_t byte = buffer_read_uint8(read_buffer);
    *((uint8_t *)first_param->value + i) = byte;
  }

  buffer_destroy(read_buffer);
  return OK;
}

status_code instruction_mov_out(
    t_list *params, t_log *logger,
    uint32_t (*translate_address)(uint32_t, uint32_t, status_code *),
    uint32_t pid, uint32_t page_size, char *server_ip, char *server_port) {
  param *first_param = list_get(params, 0);
  param *second_param = list_get(params, 1);
  uint32_t logical_address = *(uint32_t *)first_param->value;

  uint32_t size = second_param->type == EXTENDED_REGISTER ? 4 : 1;

  uint32_t write_value = *(uint32_t *)second_param->value;
  buffer_t *write_buffer = buffer_create();
  for (int i = 0; i < size; i++) {
    buffer_add_uint8(write_buffer, write_value);
  }

  status_code res_translate = OK;
  uint32_t physical_address =
      translate_address(logical_address, pid, &res_translate);
  if (res_translate == ERROR) {
    buffer_destroy(write_buffer);
    return ERROR;
  }

  uint32_t page_number = logical_address / page_size;
  uint32_t offset = logical_address - page_number * page_size;
  int remaining = size + offset - page_size;
  uint32_t split = size;
  if (remaining > 0)
    split = size - remaining;

  int client_socket = connection_create_client(server_ip, server_port);
  packet_t *req = packet_create(WRITE_DIR);
  packet_add_uint32(req, physical_address);
  packet_add_uint32(req, pid);
  packet_add_uint32(req, split);
  for (int i = 0; i < split; i++) {
    uint8_t byte = buffer_read_uint8(write_buffer);
    log_info(logger,
             "PID: %u - Accion: ESCRITURA - Direccion fisica: %u - Valor: %u",
             pid, physical_address + i, byte);
    packet_add_uint8(req, byte);
  }
  packet_send(req, client_socket);
  packet_destroy(req);
  connection_close(client_socket);

  while (remaining > 0) {
    size = remaining;
    logical_address += split;
    res_translate = OK;
    physical_address = translate_address(logical_address, pid, &res_translate);
    if (res_translate == ERROR) {
      buffer_destroy(write_buffer);
      return ERROR;
    }

    page_number = logical_address / page_size;
    offset = logical_address - page_number * page_size;
    remaining = size + offset - page_size;
    split = size;
    if (remaining > 0)
      split = size - remaining;

    client_socket = connection_create_client(server_ip, server_port);
    req = packet_create(WRITE_DIR);
    packet_add_uint32(req, physical_address);
    packet_add_uint32(req, pid);
    packet_add_uint32(req, split);
    for (int i = 0; i < split; i++) {
      uint8_t byte = buffer_read_uint8(write_buffer);
      log_info(logger,
               "PID: %u - Accion: ESCRITURA - Direccion fisica: %u - Valor: %u",
               pid, physical_address + i, byte);
      packet_add_uint8(req, byte);
    }
    packet_send(req, client_socket);
    packet_destroy(req);
    connection_close(client_socket);
  }
  buffer_destroy(write_buffer);
  return OK;
}

void instruction_resize(t_list *params, packet_t *instruction_packet,
                        uint32_t pid) {
  param *first_param = list_get(params, 0);

  packet_add_uint32(instruction_packet, pid);
  packet_add_uint32(instruction_packet, *(uint32_t *)first_param->value);
}

status_code instruction_copy_string(
    t_list *params, char *server_ip, char *server_port, t_log *logger,
    uint32_t (*translate_address)(uint32_t, uint32_t, status_code *),
    uint32_t si, uint32_t di, uint32_t pid, uint32_t page_size) {
  param *first_param = list_get(params, 0);
  uint32_t size = *(uint32_t *)first_param->value;

  uint32_t logical_address_si = si;
  uint32_t logical_address_di = di;
  status_code res_translate = OK;
  uint32_t physical_address_si =
      translate_address(logical_address_si, pid, &res_translate);
  if (res_translate == ERROR)
    return ERROR;
  res_translate = OK;
  uint32_t physical_address_di =
      translate_address(logical_address_di, pid, &res_translate);
  if (res_translate == ERROR)
    return ERROR;

  buffer_t *buffer = buffer_create();

  uint32_t page_number = logical_address_si / page_size;
  uint32_t offset = logical_address_si - page_number * page_size;
  int remaining = size + offset - page_size;
  uint32_t split = size;
  if (remaining > 0)
    split = size - remaining;

  int client_socket = connection_create_client(server_ip, server_port);
  packet_t *req = packet_create(READ_DIR);
  packet_add_uint32(req, physical_address_si);
  packet_add_uint32(req, pid);
  packet_add_uint32(req, split);
  packet_send(req, client_socket);
  packet_destroy(req);
  packet_t *res = packet_recieve(client_socket);
  for (int i = 0; i < split; i++) {
    uint8_t byte = packet_read_uint8(res);
    log_info(logger,
             "PID: %u - Accion: LECTURA - Direccion fisica: %u - Valor: %u",
             pid, physical_address_si + i, byte);
    buffer_add_uint8(buffer, byte);
  }
  packet_destroy(res);
  connection_close(client_socket);

  while (remaining > 0) {
    size = remaining;
    logical_address_si += split;
    res_translate = OK;
    physical_address_si =
        translate_address(logical_address_si, pid, &res_translate);
    if (res_translate == ERROR) {
      buffer_destroy(buffer);
      return ERROR;
    }

    page_number = logical_address_si / page_size;
    offset = logical_address_si - page_number * page_size;
    remaining = size + offset - page_size;
    split = size;
    if (remaining > 0)
      split = size - remaining;

    client_socket = connection_create_client(server_ip, server_port);
    req = packet_create(READ_DIR);
    packet_add_uint32(req, physical_address_si);
    packet_add_uint32(req, pid);
    packet_add_uint32(req, split);
    packet_send(req, client_socket);
    packet_destroy(req);
    res = packet_recieve(client_socket);
    for (int i = 0; i < split; i++) {
      uint8_t byte = packet_read_uint8(res);
      log_info(logger,
               "PID: %u - Accion: LECTURA - Direccion fisica: %u - Valor: %u",
               pid, physical_address_si + i, byte);
      buffer_add_uint8(buffer, byte);
    }
    packet_destroy(res);
    connection_close(client_socket);
  }

  size = *(uint32_t *)first_param->value;
  page_number = logical_address_di / page_size;
  offset = logical_address_di - page_number * page_size;
  remaining = size + offset - page_size;
  split = size;
  if (remaining > 0)
    split = size - remaining;

  client_socket = connection_create_client(server_ip, server_port);
  req = packet_create(WRITE_DIR);
  packet_add_uint32(req, physical_address_di);
  packet_add_uint32(req, pid);
  packet_add_uint32(req, split);
  for (int i = 0; i < split; i++) {
    uint8_t byte = buffer_read_uint8(buffer);
    log_info(logger,
             "PID: %u - Accion: ESCRITURA - Direccion fisica: %u - Valor: %u",
             pid, physical_address_di + i, byte);
    packet_add_uint8(req, byte);
  }
  packet_send(req, client_socket);
  packet_destroy(req);
  connection_close(client_socket);

  while (remaining > 0) {
    size = remaining;
    logical_address_di += split;
    res_translate = OK;
    physical_address_di =
        translate_address(logical_address_di, pid, &res_translate);
    if (res_translate == ERROR) {
      buffer_destroy(buffer);
      return ERROR;
    }

    page_number = logical_address_di / page_size;
    offset = logical_address_di - page_number * page_size;
    remaining = size + offset - page_size;
    split = size;
    if (remaining > 0)
      split = size - remaining;

    client_socket = connection_create_client(server_ip, server_port);
    req = packet_create(WRITE_DIR);
    packet_add_uint32(req, physical_address_di);
    packet_add_uint32(req, pid);
    packet_add_uint32(req, split);
    for (int i = 0; i < split; i++) {
      uint8_t byte = buffer_read_uint8(buffer);
      log_info(logger,
               "PID: %u - Accion: ESCRITURA - Direccion fisica: %u - Valor: %u",
               pid, physical_address_di + i, byte);
      packet_add_uint8(req, byte);
    }
    packet_send(req, client_socket);
    packet_destroy(req);
    connection_close(client_socket);
  }
  buffer_destroy(buffer);
  return OK;
}

status_code instruction_io_stdin(t_list *params, packet_t *instruction_packet,
                                 uint32_t (*translate_address)(uint32_t,
                                                               uint32_t,
                                                               status_code *),
                                 uint32_t pid, uint32_t page_size) {
  param *first_param = list_get(params, 0);
  param *second_param = list_get(params, 1);
  param *third_param = list_get(params, 2);
  packet_add_string(instruction_packet, (char *)first_param->value);
  packet_add_uint32(instruction_packet, pid);
  uint32_t size = *(uint32_t *)third_param->value;
  packet_add_uint32(instruction_packet, size);
  uint32_t logical_address = *(uint32_t *)second_param->value;
  status_code res_translate = OK;
  uint32_t physical_address =
      translate_address(logical_address, pid, &res_translate);
  if (res_translate == ERROR)
    return ERROR;

  uint32_t page_number = logical_address / page_size;
  uint32_t offset = logical_address - page_number * page_size;
  int remaining = size + offset - page_size;
  uint32_t split = size - remaining;
  if (remaining > 0)
    split = size - remaining;
  uint32_t splits = remaining <= 0 ? 1 : 1 + ceil_div(remaining, page_size);
  packet_add_uint32(instruction_packet, splits);
  packet_add_uint32(instruction_packet, physical_address);
  packet_add_uint32(instruction_packet, split);

  while (remaining > 0) {
    size = remaining;
    logical_address += split;
    res_translate = OK;
    physical_address = translate_address(logical_address, pid, &res_translate);
    if (res_translate == ERROR)
      return ERROR;

    page_number = logical_address / page_size;
    offset = logical_address - page_number * page_size;
    remaining = size + offset - page_size;
    split = size;
    if (remaining > 0)
      split = size - remaining;
    packet_add_uint32(instruction_packet, physical_address);
    packet_add_uint32(instruction_packet, split);
  }
  return OK;
}

status_code instruction_io_stdout(t_list *params, packet_t *instruction_packet,
                                  uint32_t (*translate_address)(uint32_t,
                                                                uint32_t,
                                                                status_code *),
                                  uint32_t pid, uint32_t page_size) {
  param *first_param = list_get(params, 0);
  param *second_param = list_get(params, 1);
  param *third_param = list_get(params, 2);
  packet_add_string(instruction_packet, (char *)first_param->value);
  packet_add_uint32(instruction_packet, pid);

  uint32_t size = *(uint32_t *)third_param->value;
  uint32_t logical_address = *(uint32_t *)second_param->value;
  status_code res_translate = OK;
  uint32_t physical_address =
      translate_address(logical_address, pid, &res_translate);
  if (res_translate == ERROR)
    return ERROR;

  uint32_t page_number = logical_address / page_size;
  uint32_t offset = logical_address - page_number * page_size;
  int remaining = size + offset - page_size;
  uint32_t split = size - remaining;
  if (remaining > 0)
    split = size - remaining;
  uint32_t splits = remaining <= 0 ? 1 : 1 + ceil_div(remaining, page_size);
  packet_add_uint32(instruction_packet, splits);
  packet_add_uint32(instruction_packet, physical_address);
  packet_add_uint32(instruction_packet, split);

  while (remaining > 0) {
    size = remaining;
    logical_address += split;
    res_translate = OK;
    physical_address = translate_address(logical_address, pid, &res_translate);
    if (res_translate == ERROR)
      return ERROR;

    page_number = logical_address / page_size;
    offset = logical_address - page_number * page_size;
    remaining = size + offset - page_size;
    split = size;
    if (remaining > 0)
      split = size - remaining;
    packet_add_uint32(instruction_packet, physical_address);
    packet_add_uint32(instruction_packet, split);
  }
  return OK;
}

void instruction_io_fs_create(t_list *params, packet_t *instruction_packet,
                              t_log *logger, uint32_t pid) {
  char *interface_name = ((param *)list_get(params, 0))->value;
  char *file_name = ((param *)list_get(params, 1))->value;

  packet_add_string(instruction_packet, interface_name);
  packet_add_string(instruction_packet, file_name);
  packet_add_uint32(instruction_packet, pid);
}

void instruction_io_fs_delete(t_list *parms, packet_t *instruction_packet,
                              t_log *logger, uint32_t pid) {}

void instruction_io_fs_read(t_list *parms, packet_t *instruction_packet,
                            t_log *logger, uint32_t pid) {}

void instruction_io_fs_write(t_list *parms, packet_t *instruction_packet,
                             t_log *logger, uint32_t pid) {}

void instruction_io_fs_truncate(t_list *parms, packet_t *instruction_packet,
                                t_log *logger, uint32_t pid) {}

void instruction_wait(t_list *params, packet_t *instruction_packet,
                      t_log *logger, uint32_t pid) {
  char *resource = ((param *)list_get(params, 0))->value;

  packet_add_string(instruction_packet, resource);
  packet_add_uint32(instruction_packet, pid);
}

void instruction_signal(t_list *params, packet_t *instruction_packet,
                        t_log *logger, uint32_t pid) {
  char *resource = ((param *)list_get(params, 0))->value;

  packet_add_string(instruction_packet, resource);
  packet_add_uint32(instruction_packet, pid);
}

void instruction_exit() {}
