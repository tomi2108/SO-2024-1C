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

t_list *tlb;
int cantidad_entradas_tlb;
char *algoritmo_tlb;

int dealloc = 0;
int tamanio_pagina;

uint32_t pc = 4;

uint8_t ax = 1;
uint8_t bx = 1;
uint8_t cx = 1;
uint8_t dx = 1;

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

typedef struct t_tlb {
  uint32_t pid;
  int page_number;
  int num_marco;
} t_tlb;

t_tlb *search_tlb(uint32_t pid, int page_number, int *index) {
  for (int i = 0; i < list_size(tlb); i++) {
    t_tlb *entry = list_get(tlb, i);
    if (entry->pid == pid && entry->page_number == page_number) {
      *index = i;
      return entry;
    }
  }
  return NULL;
}

status_code nro_frame_tlb(uint32_t pid, int page_number,
                          uint32_t *frame_number) {
  int index = 0;
  t_tlb *entry = search_tlb(pid, page_number, &index);
  if (!entry) {
    log_info(logger, "PID: %d - TLB MISS - Pagina: %d", pid, page_number);
    return ERROR;
  } else {
    *frame_number = entry->num_marco;
    log_info(logger, "PID: %d - TLB HIT - Pagina: %d", pid, page_number);
    if (strcmp(algoritmo_tlb, "LRU") == 0) {
      t_tlb *removed_entry = list_remove(tlb, index);
      list_add(tlb, removed_entry);
    }
    return OK;
  }
}

status_code solicitar_marco_de_memoria(uint32_t pid, int page_number,
                                       uint32_t *frame_number) {
  int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);
  if (socket_memoria == -1) {
    log_error(logger, "Error al conectarse con memoria");
    return ERROR;
  }

  packet_t *req = packet_create(FETCH_FRAME_NUMBER);
  packet_add_uint32(req, pid);
  packet_add_uint32(req, page_number);
  packet_send(req, socket_memoria);
  packet_destroy(req);

  packet_t *res = packet_recieve(socket_memoria);
  connection_close(socket_memoria);

  if (res == NULL) {
        log_error(logger, "Error al recibir respuesta de memoria");
        return ERROR;
    }

    *frame_number = packet_read_uint32(res);
    log_info(logger, "PID: %d - OBTENER MARCO - Página: %d - Marco: %d", pid, page_number, *frame_number);
    packet_destroy(res);
    return OK;
}

status_code solicitar_tamanio_pagina() {
  int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);
  if (socket_memoria == -1) {
    log_error(logger, "Error al conectarse con memoria");
    return ERROR;
  }

  packet_t *req = packet_create(TAMANIO_PAGINA_REQUEST);
  packet_send(req, socket_memoria);
  packet_destroy(req);

  packet_t *res = packet_recieve(socket_memoria);
  connection_close(socket_memoria);

  if (res == NULL || res->type != TAMANIO_PAGINA_RESPONSE) {
    log_error(logger, "Error al recibir respuesta de memoria para tamaño de página");
    if (res != NULL) packet_destroy(res);
    return ERROR;
  }

  tamanio_pagina = packet_read_uint8(res);
  packet_destroy(res);

  //log_info(logger, "Tamaño de página recibido: %d bytes", tamanio_pagina);
  return OK;
}

void actualizar_tlb(uint32_t pid, uint32_t frame_number, int page_number) {
  t_tlb *new_entry = malloc(sizeof(t_tlb));
  new_entry->pid = pid;
  new_entry->page_number = page_number;
  new_entry->num_marco = frame_number;

  if (list_size(tlb) >= cantidad_entradas_tlb) {
    // Implementar política de reemplazo
    if (strcmp(algoritmo_tlb, "FIFO") == 0) {
      list_remove_and_destroy_element(tlb, 0, &free); // Elimina la entrada más antigua
    } else if (strcmp(algoritmo_tlb, "LRU") == 0) {
      // La política LRU implica mover la entrada más reciente al final, así que
      // aquí solo eliminamos el primer elemento como en FIFO.
      list_remove_and_destroy_element(tlb, 0, &free);
    }
  }

  list_add(tlb, new_entry);
}

int numero_pagina(uint32_t logical_address) {
  if (tamanio_pagina == 0) {
    log_error(logger,
              "El tamaño de página es 0, no se puede realizar la división.");
    exit_input_error(logger);
  }
  return logical_address / tamanio_pagina;
}

int calcular_desplazamiento(uint32_t logical_addres, int numero_pagina) {
  return logical_addres - numero_pagina * tamanio_pagina;
}

uint32_t translate_address(uint32_t logical_address, uint32_t pid) {
  log_info(logger, "Traduciendo dirección lógica %u para el PID %d", logical_address, pid);
  int page_number = numero_pagina(logical_address);

  if (page_number < 0) {
    log_error(logger, "Número de página inválido: %d", page_number);
    exit_input_error(logger);
  }

  int offset = calcular_desplazamiento(logical_address, page_number);

  uint32_t frame_number;
  status_code tlb_search_result =
      nro_frame_tlb(pid, page_number, &frame_number);

  if (tlb_search_result == ERROR) {
    // TLB Miss
    status_code request_result =
        solicitar_marco_de_memoria(pid, page_number, &frame_number);
    if (request_result == ERROR) {
      log_error(logger,"Error al consultar la Memoria para la página %d del PID %d",page_number, pid);
      exit_input_error(logger);
    }

    // Actualizar la TLB con el nuevo marco obtenido
    actualizar_tlb(pid, frame_number, page_number);
  }

  // Dirección física = (marco * tamaño de página) + desplazamiento
  uint32_t physical_address = (frame_number * tamanio_pagina) + offset;
  log_info(logger, "Dirección fisica %u", physical_address);
  
  return physical_address;
}

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
  case EXIT:
    instruction_exit();
    break;
  case COPY_STRING:
    int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);
    instruction_copy_string(params, socket_memoria, logger, &translate_address, si, di, pid);
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
  si = 0;
  di = 0;
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
  process -> registers.si = si;
  process -> registers.di = di;
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
  si = process.registers.si;
  di = process.registers.di;
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

  if (solicitar_tamanio_pagina() == ERROR) {
    log_error(logger, "No se pudo obtener el tamaño de página. Finalizando...");
    exit(EXIT_FAILURE);
  }

  sem_init(&sem_check_interrupt, 1, 1);
  sem_init(&sem_process_interrupt, 1, 0);

  pthread_mutex_init(&mutex_dealloc, NULL);

  tlb = list_create();

  pthread_t servers[2];
  pthread_create(&servers[0], NULL, &server_dispatch, NULL);
  pthread_create(&servers[1], NULL, &server_interrupt, NULL);

  pthread_join(servers[0], NULL);
  pthread_join(servers[1], 0);

  sem_destroy(&sem_check_interrupt);
  sem_destroy(&sem_process_interrupt);
  pthread_mutex_destroy(&mutex_dealloc);
  list_destroy_and_destroy_elements(tlb, &free);

  log_destroy(logger);
  config_destroy(config);
  return EXIT_SUCCESS;
}
