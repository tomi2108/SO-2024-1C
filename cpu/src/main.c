#include <commons/collections/list.h>
#include <commons/config.h>
#include <commons/log.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <utils/connection.h>
#include <utils/exit.h>
#include <utils/instruction.h>
#include <utils/packet.h>
#include <utils/process.h>
#include <utils/status.h>

t_log *logger;
t_config *config;

char *puerto_dispatch;
char *puerto_interrupt;

char *ip_memoria;
char *puerto_memoria;

int cantidad_entradas_tlb;
char *algoritmo_tlb;

int dealloc = 0;

uint32_t pc = 0;

uint8_t ax = 0;
uint8_t bx = 0;
uint8_t cx = 0;
uint8_t dx = 0;

uint32_t eax = 0;
uint32_t ebx = 0;
uint32_t ecx = 0;
uint32_t edx = 0;

uint32_t si = 0;
uint32_t di = 0;

sem_t sem_check_interrupt;
sem_t sem_process_interrupt;

pthread_mutex_t mutex_dealloc;

uint32_t strtoui32(char *s, int *is_number) {
  *is_number = 1;
  for (int i = 0; i < strlen(s); i++) {
    if (!isdigit(s[i])) {
      *is_number = 0;
      break;
    }
  }

  return strtol(s, NULL, 10);
}

uint32_t translate_address(uint32_t logical_addres) { return logical_addres; }

char *request_fetch_instruction(process_t process) {
  int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);
  if (socket_memoria == -1)
    exit_client_connection_error(logger);

  packet_t *req = packet_create(FETCH_INSTRUCTION);
  packet_add_uint32(req, pc);
  packet_add_string(req, process.path);
  packet_send(req, socket_memoria);
  packet_destroy(req);
  log_info(logger, "PID: %u - FETCH - Program Counter: %u", process.pid, pc);

  packet_t *res = packet_recieve(socket_memoria);
  char *instruction;
  switch (res->type) {
  case INSTRUCTION:
    instruction = packet_read_string(res);
    break;
  case STATUS: {
    status_code status = status_unpack(res);
    if (status == END_OF_FILE) {
      instruction = NULL;
    }
    break;
  }
  default:
    break;
  }
  packet_destroy(res);
  connection_close(socket_memoria);
  return instruction;
}

uint8_t *is_register(char *token) {
  if (strcmp(token, "AX") == 0)
    return &ax;
  if (strcmp(token, "BX") == 0)
    return &bx;
  if (strcmp(token, "CX") == 0)
    return &cx;
  if (strcmp(token, "DX") == 0)
    return &dx;
  return NULL;
}

uint32_t *is_extended_register(char *token) {
  if (strcmp(token, "EAX") == 0)
    return &eax;
  if (strcmp(token, "EBX") == 0)
    return &ebx;
  if (strcmp(token, "ECX") == 0)
    return &ecx;
  if (strcmp(token, "EDX") == 0)
    return &edx;
  return NULL;
}

instruction_op decode_instruction(char *instruction, t_list *params) {

  char *token = strtok(instruction, " ");
  if (token == NULL)
    return UNKNOWN_INSTRUCTION;

  instruction_op op = instruction_op_from_string(token);

  token = strtok(NULL, " ");
  while (token != NULL) {

    uint8_t *reg = is_register(token);
    if (reg != NULL) {
      param *p = malloc(sizeof(param));
      p->type = REGISTER;
      p->value = reg;
      list_add(params, p);
      token = strtok(NULL, " ");
      continue;
    }

    uint32_t *extended_register = is_extended_register(token);
    if (extended_register != NULL) {
      param *p = malloc(sizeof(param));
      p->type = REGISTER;
      p->value = extended_register;
      list_add(params, p);
      token = strtok(NULL, " ");
      continue;
    }

    int is_number = 0;
    errno = 0;
    uint32_t n = strtoui32(token, &is_number);
    if (is_number && !errno) {
      uint32_t *number = malloc(sizeof(uint32_t));
      memcpy(number, &n, sizeof(uint32_t));
      param *p = malloc(sizeof(param));
      p->type = NUMBER;
      p->value = number;
      list_add(params, p);
      token = strtok(NULL, " ");
      continue;
    }

    param *p = malloc(sizeof(param));
    p->type = STRING;
    p->value = token;
    list_add(params, p);
    token = strtok(NULL, " ");
  }
  return op;
}

void exec_instruction(instruction_op op, t_list *params,
                      packet_t *instruction_packet, uint32_t pid) {
  switch (op) {
  case SET:
    instruction_set(params);
    break;
  case SUM:
    instruction_sum(params);
    break;
  case SUB:
    instruction_sub(params);
    break;
  case JNZ:
    instruction_jnz(params, &pc);
    break;
  case IO_GEN_SLEEP:
    instruction_io_gen_sleep(params, instruction_packet);
    break;
  case MOV_IN: {
    int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);
    instruction_mov_in(params, socket_memoria, logger, &translate_address, pid);
    connection_close(socket_memoria);
    break;
  }
  case MOV_OUT: {
    int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);
    instruction_mov_out(params, socket_memoria, logger, &translate_address,
                        pid);
    connection_close(socket_memoria);
    break;
  }
  case RESIZE:
    instruction_resize(params, instruction_packet, pid);
    break;
  case IO_STDIN_READ:
    instruction_io_stdin(params, instruction_packet, &translate_address, pid);
    break;
  case IO_STDOUT_WRITE:
    instruction_io_stdout(params, instruction_packet, &translate_address, pid);
    break;
  case IO_FS_CREATE:
    instruction_io_fs_create(params, instruction_packet, logger, pid);
    break;
  case IO_FS_DELETE:
    instruction_io_fs_delete(params, instruction_packet, logger, pid);
    break;
  case IO_FS_READ:
    instruction_io_fs_read(params, instruction_packet, logger, pid);
    break;
  case IO_FS_WRITE:
    instruction_io_fs_write(params, instruction_packet, logger, pid);
    break;
  case IO_FS_TRUNCATE:
    instruction_io_fs_truncate(params, instruction_packet, logger, pid);
    break;
  case WAIT:
    instruction_wait(params, instruction_packet, logger, pid);
    break;
  case SIGNAL:
    instruction_signal(params, instruction_packet, logger, pid);
    break;
  default:
    break;
  }
}

void free_param(void *p) {
  param *parameter = (param *)p;
  free(parameter);
}

void reset_registers() {
  pc = 0;
  bx = 0;
  ax = 0;
  cx = 0;
  dx = 0;
  eax = 0;
  ebx = 0;
  ecx = 0;
  edx = 0;
}

void load_registers(process_t *process) {
  process->program_counter = pc;
  process->registers.ax = ax;
  process->registers.bx = bx;
  process->registers.cx = cx;
  process->registers.dx = dx;
  process->registers.eax = eax;
  process->registers.ebx = ebx;
  process->registers.ecx = ecx;
  process->registers.edx = edx;
}

void unload_registers(process_t process) {
  pc = process.program_counter;
  ax = process.registers.ax;
  bx = process.registers.bx;
  cx = process.registers.cx;
  dx = process.registers.dx;
  eax = process.registers.eax;
  ebx = process.registers.ebx;
  ecx = process.registers.ecx;
  edx = process.registers.edx;
}

void response_exec_process(packet_t *req, int client_socket) {
  int interrupted = 0;
  process_t process = process_unpack(req);
  unload_registers(process);
  // fetch
  char *instruction = request_fetch_instruction(process);
  while (instruction != NULL && !interrupted) {
    pc++;
    t_list *params = list_create();

    // decode
    instruction_op operation = decode_instruction(instruction, params);

    // exec
    packet_t *packet = packet_create(INSTRUCTION);
    packet_add(packet, &operation, sizeof(instruction_op));

    exec_instruction(operation, params, packet, process.pid);
    log_info(logger, "PID: %u - Ejecutando: %s", process.pid, instruction);
    list_destroy_and_destroy_elements(params, &free_param);

    packet_send(packet, client_socket);
    packet_destroy(packet);

    // check interrupt
    sem_wait(&sem_process_interrupt);
    pthread_mutex_lock(&mutex_dealloc);
    if (dealloc == 1)
      interrupted = 1;
    pthread_mutex_unlock(&mutex_dealloc);
    sem_post(&sem_check_interrupt);

    // fetch
    pthread_mutex_lock(&mutex_dealloc);
    if (dealloc == 0) {
      free(instruction);
      instruction = request_fetch_instruction(process);
    }
    pthread_mutex_unlock(&mutex_dealloc);
  }
  dealloc = 0;
  load_registers(&process);
  reset_registers();
  packet_t *res = process_pack(process);
  status_code status = instruction == NULL ? END_OF_FILE : OK;
  packet_add(res, &status, sizeof(status_code));
  packet_send(res, client_socket);
  packet_destroy(res);
}

void *server_dispatch(void *args) {
  int server_socket = connection_create_server(puerto_dispatch);
  if (server_socket == -1)
    exit_server_connection_error(logger);

  log_info(logger, "Servidor dispatch levantado en el puerto %s",
           puerto_dispatch);

  while (1) {
    int client_socket = connection_accept_client(server_socket);
    if (client_socket == -1)
      continue;
    packet_t *req = packet_recieve(client_socket);

    if (req == NULL)
      break;
    switch (req->type) {
    case PROCESS:
      response_exec_process(req, client_socket);
      break;
    default:
      break;
    }
    packet_destroy(req);
    connection_close(client_socket);
  }
  connection_close(server_socket);
  return args;
}

void *server_interrupt(void *args) {
  int server_socket = connection_create_server(puerto_interrupt);

  if (server_socket == -1)
    exit_server_connection_error(logger);

  log_info(logger, "Servidor interrupt levantado en el puerto %s",
           puerto_interrupt);

  while (1) {
    sem_wait(&sem_check_interrupt);
    int client_socket = connection_accept_client(server_socket);
    packet_t *req = packet_recieve(client_socket);
    switch (req->type) {
    case INTERRUPT: {
      pthread_mutex_lock(&mutex_dealloc);
      dealloc = 1;
      pthread_mutex_unlock(&mutex_dealloc);
      break;
    }
    default:
      break;
    }
    sem_post(&sem_process_interrupt);
    packet_destroy(req);
    connection_close(client_socket);
  }
  connection_close(server_socket);
  return args;
}

int main(int argc, char *argv[]) {

  logger = log_create("cpu.log", "CPU", 1, LOG_LEVEL_DEBUG);

  if (argc < 2)
    exit_not_enough_arguments_error(logger);

  config = config_create(argv[1]);
  if (config == NULL)
    exit_enoent_error(logger, argv[1]);

  puerto_dispatch = config_get_string_value(config, "PUERTO_ESCUCHA_DISPATCH");
  puerto_interrupt =
      config_get_string_value(config, "PUERTO_ESCUCHA_INTERRUPT");

  ip_memoria = config_get_string_value(config, "IP_MEMORIA");
  puerto_memoria = config_get_string_value(config, "PUERTO_MEMORIA");

  cantidad_entradas_tlb = config_get_int_value(config, "CANTIDAD_ENTRADAS_TLB");
  algoritmo_tlb = config_get_string_value(config, "ALGORITMO_TLB");

  sem_init(&sem_check_interrupt, 1, 1);
  sem_init(&sem_process_interrupt, 1, 0);

  pthread_mutex_init(&mutex_dealloc, NULL);

  pthread_t servers[2];
  pthread_create(&servers[0], NULL, &server_dispatch, NULL);
  pthread_create(&servers[1], NULL, &server_interrupt, NULL);

  pthread_join(servers[0], NULL);
  pthread_join(servers[1], 0);

  sem_destroy(&sem_check_interrupt);
  sem_destroy(&sem_process_interrupt);
  pthread_mutex_destroy(&mutex_dealloc);

  log_destroy(logger);
  config_destroy(config);
  return EXIT_SUCCESS;
}
