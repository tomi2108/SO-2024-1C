#include <commons/collections/list.h>
#include <commons/config.h>
#include <commons/log.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <string.h>
#include <utils/connection.h>
#include <utils/instruction.h>
#include <utils/packet.h>
#include <utils/process.h>

t_log *logger;
t_config *config;

char *puerto_dispatch;
char *puerto_interrupt;

char *ip_memoria;
char *puerto_memoria;

int cantidad_entradas_tlb;
char *algoritmo_tlb;

uint32_t pc = 0;

uint8_t ax = 0;
uint8_t bx = 12;
uint8_t cx = 0;
uint8_t dx = 0;

uint32_t eax = 17;
uint32_t ebx = 0;
uint32_t ecx = 0;
uint32_t edx = 0;

uint32_t si = 0;
uint32_t di = 0;

sem_t sem_check_interrupt;
sem_t sem_process_interrupt;

int dealloc = 0;

char *request_fetch_instruction(process_t process) {
  int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);
  if (socket_memoria == -1) {
    log_error(logger, "Imposible conectarse con la memoria");
    exit(5);
  }
  packet_t *req = packet_create(FETCH_INSTRUCTION);
  packet_add_uint32(req, process.program_counter);
  packet_add_string(req, process.path);
  packet_send(req, socket_memoria);
  packet_destroy(req);

  packet_t *res = packet_recieve(socket_memoria);
  char *instruction;
  if (res->type == INSTRUCTION) {
    instruction = packet_read_string(res);
  } else
    instruction = NULL;
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
      p->type = EXTENDED_REGISTER;
      p->value = extended_register;
      list_add(params, p);
      token = strtok(NULL, " ");
      continue;
    }

    long *number = malloc(sizeof(long));
    long n = strtol(token, NULL, 10);
    memcpy(number, &n, sizeof(long));

    if (*number != 0 && errno != EINVAL) {
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

void exec_instruction(instruction_op op, t_list *params, int client_socket) {
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
  case IO_GEN_SLEEP: {
    instruction_io_gen_sleep(params, client_socket);
    break;
  }
  default:
    break;
  }
}

void free_param(void *p) {
  param *parameter = (param *)p;
  free(parameter);
}

void response_exec_process(packet_t *req, int client_socket) {
  process_t process = process_unpack(req);

  char *instruction = request_fetch_instruction(process);

  while (instruction != NULL) {
    t_list *params = list_create();

    instruction_op operation = decode_instruction(instruction, params);

    log_debug(logger, "[DISPATCH] Ejecutando instruccion %s",
              instruction_op_to_string(operation));
    fflush(stdout);

    exec_instruction(operation, params, client_socket);
    process.quantum--;
    process.program_counter++;

    if (!instruction_is_blocking(operation)) {
      packet_t *packet = packet_create(NON_BLOCKING_OP);
      packet_send(packet, client_socket);
    }

    packet_t *res = process_pack(process);
    packet_send(res, client_socket);

    sem_wait(&sem_process_interrupt);
    if (dealloc == 1) {
      log_debug(logger, "[DISPATCH] Desalojando proceso");
      fflush(stdout);
    } else {
      log_debug(logger, "[DISPATCH] La ejecucion continua");
      fflush(stdout);
    }
    dealloc = 0;
    sem_post(&sem_check_interrupt);
    list_destroy_and_destroy_elements(params, &free_param);
    log_debug(logger, "[DISPATCH] Siguiente instruccion");
    fflush(stdout);
    instruction = request_fetch_instruction(process);
  }
}

void *server_dispatch(void *args) {
  int server_socket = connection_create_server(puerto_dispatch);
  if (server_socket == -1) {
    log_error(logger, "Imposible crear el servidor dispatch");
    exit(3);
  }

  log_info(logger, "Servidor dispatch levantado en el puerto %s",
           puerto_dispatch);

  while (1) {
    int client_socket = connection_accept_client(server_socket);
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

void check_interrupt(packet_t *req) {
  log_debug(logger, "[INTERRUPT] Se recibio una interrupcion, procesando....");
  fflush(stdout);
  uint8_t message = packet_read_uint8(req);
  if (message != 0)
    dealloc = 1;
  else
    dealloc = 0;
  sem_post(&sem_process_interrupt);
}

void *server_interrupt(void *args) {
  int server_socket = connection_create_server(puerto_interrupt);

  if (server_socket == -1) {
    log_error(logger, "Imposible crear el servidor interrupt");
    exit(4);
  }

  log_info(logger, "Servidor interrupt levantado en el puerto %s",
           puerto_interrupt);

  while (1) {
    sem_wait(&sem_check_interrupt);
    int client_socket = connection_accept_client(server_socket);
    packet_t *req = packet_recieve(client_socket);
    if (req == NULL)
      break;
    switch (req->type) {
    case INTERRUPT: {
      check_interrupt(req);
      packet_destroy(req);
      connection_close(client_socket);
      break;
    }
    default:
      break;
    }
  }
  connection_close(server_socket);
  return args;
}

int main(int argc, char *argv[]) {

  logger = log_create("cpu.log", "CPU", 1, LOG_LEVEL_DEBUG);

  if (argc < 2) {
    log_error(logger, "Especificar archivo de configuracion");
    return 1;
  }

  config = config_create(argv[1]);
  if (config == NULL) {
    log_error(logger, "Error al crear la configuracion");
    return 2;
  }

  puerto_dispatch = config_get_string_value(config, "PUERTO_ESCUCHA_DISPATCH");
  puerto_interrupt =
      config_get_string_value(config, "PUERTO_ESCUCHA_INTERRUPT");

  ip_memoria = config_get_string_value(config, "IP_MEMORIA");
  puerto_memoria = config_get_string_value(config, "PUERTO_MEMORIA");

  cantidad_entradas_tlb = config_get_int_value(config, "CANTIDAD_ENTRADAS_TLB");
  algoritmo_tlb = config_get_string_value(config, "ALGORITMO_TLB");

  sem_init(&sem_check_interrupt, 1, 1);
  sem_init(&sem_process_interrupt, 1, 0);

  pthread_t servers[2];
  pthread_create(&servers[0], NULL, &server_dispatch, NULL);
  pthread_create(&servers[1], NULL, &server_interrupt, NULL);

  pthread_join(servers[0], NULL);
  pthread_join(servers[1], 0);

  sem_destroy(&sem_check_interrupt);
  sem_destroy(&sem_process_interrupt);
  log_destroy(logger);
  config_destroy(config);
  return 0;
}
