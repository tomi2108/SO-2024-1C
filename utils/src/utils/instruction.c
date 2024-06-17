#include "instruction.h"

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

void instruction_mov_in(t_list *params, int client_socket, t_log *logger,
                        uint32_t (*translate_address)(uint32_t, uint32_t),
                        uint32_t pid) {
  param *first_param = list_get(params, 0);
  param *second_param = (param *)list_get(params, 1);

  uint32_t logical_address = *(uint32_t *)second_param->value;
  uint32_t physical_address = translate_address(logical_address, pid);

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

void instruction_mov_out(t_list *params, t_log *logger,
                         uint32_t (*translate_address)(uint32_t, uint32_t),
                         uint32_t pid, uint32_t page_size, char *server_ip,
                         char *server_port, buffer_t *write_buffer) {
  param *first_param = list_get(params, 0);
  param *second_param = list_get(params, 1);
  uint32_t logical_address = *(uint32_t *)first_param->value;
  uint32_t write_value = *(uint32_t *)second_param->value;

  uint32_t size = 4;

  if (write_buffer == NULL) {
    write_buffer = buffer_create();
    buffer_add_uint32(write_buffer, write_value);
  } else {
    size = write_buffer->size - write_buffer->offset;
  }

  uint32_t physical_address = translate_address(logical_address, pid);

  uint32_t page_number = logical_address / page_size;
  uint32_t offset = logical_address - page_number * page_size;
  int remaining = size + offset - page_size;
  uint8_t split = size;
  if (remaining > 0)
    split = size - remaining;

  int client_socket = connection_create_client(server_ip, server_port);
  packet_t *req = packet_create(WRITE_DIR);
  packet_add_uint32(req, physical_address);
  packet_add_uint32(req, pid);
  packet_add_uint32(req, split);
  for (int i = 0; i < split; i++) {
    uint8_t byte = buffer_read_uint8(write_buffer);
    packet_add_uint8(req, byte);
  }
  packet_send(req, client_socket);
  packet_destroy(req);

  if (remaining > 0) {
    t_list *new_params = list_create();
    uint32_t new_address = logical_address + split;
    param new_first_param = {.type = NUMBER, .value = &new_address};
    param new_second_param = {.type = NUMBER, .value = &write_value};
    list_add(new_params, &new_first_param);
    list_add(new_params, &new_second_param);
    instruction_mov_out(new_params, logger, translate_address, pid, page_size,
                        server_ip, server_port, write_buffer);
    list_destroy(new_params);
  } else {
    buffer_destroy(write_buffer);
  }

  log_info(logger,
           "PID: %u - Accion: ESCRITURA - Direccion fisica: %u - Valor: %u",
           pid, physical_address, write_value);
}

void instruction_resize(t_list *params, packet_t *instruction_packet,
                        uint32_t pid) {
  param *first_param = list_get(params, 0);

  packet_add_uint32(instruction_packet, pid);
  packet_add_uint32(instruction_packet, *(uint32_t *)first_param->value);
}

void instruction_copy_string(t_list *params, char *server_ip, char *server_port,
                             t_log *logger,
                             uint32_t (*translate_address)(uint32_t, uint32_t),
                             uint32_t si, uint32_t di, uint32_t pid,
                             uint32_t page_size, buffer_t *write_buffer) {
  param *first_param = list_get(params, 0);
  uint32_t size = *(uint32_t *)first_param->value;

  if (write_buffer == NULL) {
    // Obtener dirección física de si
    uint32_t physical_address_si = translate_address(si, pid);

    // Enviar solicitud de lectura a si
    packet_t *req = packet_create(READ_DIR);
    packet_add_uint32(req, physical_address_si);
    packet_add_uint32(req, pid);
    packet_add_uint32(req, size);
    int socket_read = connection_create_client(server_ip, server_port);
    packet_send(req, socket_read);
    log_info(logger,
             "PID: %u - Accion: LECTURA - Direccion fisica: %u - Tamaño: %u",
             pid, physical_address_si, size);
    packet_destroy(req);

    // Recibir respuesta de lectura
    packet_t *read_response = packet_recieve(socket_read);
    write_buffer = buffer_create();
    for (uint32_t i = 0; i < size; i++) {
      uint8_t byte = packet_read_uint8(read_response);
      buffer_add_uint8(write_buffer, byte);
    }
    connection_close(socket_read);
    packet_destroy(read_response);
  }

  uint32_t page_number = di / page_size;
  uint32_t offset = di - page_number * page_size;
  int remaining = size + offset - page_size;
  uint8_t split = size;
  if (remaining > 0)
    split = size - remaining;

  // Obtener dirección física de di
  uint32_t physical_address_di = translate_address(di, pid);

  // Enviar solicitud de escritura a di
  packet_t *res = packet_create(WRITE_DIR);
  packet_add_uint32(res, physical_address_di);
  packet_add_uint32(res, pid);
  packet_add_uint32(res, split);
  for (uint32_t i = 0; i < split; i++) {
    uint8_t byte = buffer_read_uint8(write_buffer);
    packet_add_uint8(res, byte);
  }
  int socket_write = connection_create_client(server_ip, server_port);
  packet_send(res, socket_write);
  connection_close(socket_write);
  packet_destroy(res);

  if (remaining > 0) {
    t_list *new_params = list_create();
    param new_first_param = {.type = NUMBER, .value = &remaining};
    list_add(new_params, &new_first_param);

    uint32_t new_di = di + split;
    instruction_copy_string(new_params, server_ip, server_port, logger,
                            translate_address, si, new_di, pid, page_size,
                            write_buffer);
    list_destroy(new_params);
  } else {
    buffer_destroy(write_buffer);
  }

  log_info(logger, "PID: %u - Accion: ESCRITURA - Direccion fisica: %u", pid,
           physical_address_di);
}

void instruction_io_stdin(t_list *params, packet_t *instruction_packet,
                          uint32_t (*translate_addres)(uint32_t, uint32_t),
                          uint32_t pid) {

  param *first_param = list_get(params, 0);
  param *second_param = list_get(params, 1);
  param *third_param = list_get(params, 2);

  packet_add_string(instruction_packet, (char *)first_param->value);

  packet_add_uint32(instruction_packet,
                    translate_addres(*(uint32_t *)second_param->value, pid));
  packet_add_uint32(instruction_packet, pid);
  packet_add_uint32(instruction_packet, *(uint32_t *)third_param->value);
}

void instruction_io_stdout(t_list *params, packet_t *instruction_packet,
                           uint32_t (*translate_addres)(uint32_t, uint32_t),
                           uint32_t pid) {

  param *first_param = list_get(params, 0);
  param *second_param = list_get(params, 1);
  param *third_param = list_get(params, 2);

  packet_add_string(instruction_packet, (char *)first_param->value);

  packet_add_uint32(instruction_packet,
                    translate_addres(*(uint32_t *)second_param->value, pid));
  packet_add_uint32(instruction_packet, pid);
  packet_add_uint32(instruction_packet, *(uint32_t *)third_param->value);
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
