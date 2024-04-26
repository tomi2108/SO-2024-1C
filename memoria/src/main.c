#include <commons/collections/list.h>
#include <commons/config.h>
#include <commons/log.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <utils/connection.h>
#include <utils/exit.h>
#include <utils/file.h>
#include <utils/instruction.h>
#include <utils/packet.h>
#include <utils/status.h>

#define FILE_LINE_MAX_LENGTH 80

t_log *logger;
t_config *config;

char *puerto_escucha;

int tam_memoria;
int tam_pagina;
int frame_count;
int retardo_respuesta;
char *path_instrucciones;

void *user_memory;
int next_page = 1;

t_list *page_table;
typedef struct {
  uint32_t pid;
  int is_free;
  uint32_t page;
} frame;

int ceil_div(uint32_t num, int denom) { return (num + denom - 1) / denom; }

char *fetch_instruction(uint32_t program_counter, char *instruction_path) {
  char *full_path = file_concat_path(path_instrucciones, instruction_path);

  FILE *file = fopen(full_path, "r");
  if (file == NULL)
    exit_enoent_error(logger, full_path);

  free(full_path);
  char *line = file_read_n_line(file, program_counter, FILE_LINE_MAX_LENGTH);
  fclose(file);

  return line;
}

int get_next_free_frame(t_list *table) {
  t_list_iterator *iterator = list_iterator_create(table);

  frame *next_frame = list_iterator_next(iterator);
  while (next_frame->is_free == 0 || !list_iterator_has_next(iterator))
    next_frame = list_iterator_next(iterator);

  if (next_frame->is_free == 0) {
    list_iterator_destroy(iterator);
    return -1;
  }

  int i = list_iterator_index(iterator);
  list_iterator_destroy(iterator);
  return i;
}

int get_frame_from_page(t_list *table, uint32_t page) {
  t_list_iterator *iterator = list_iterator_create(table);
  frame *next_frame = list_iterator_next(iterator);

  while (next_frame->is_free == 1 || next_frame->page != page ||
         !list_iterator_has_next(iterator))
    next_frame = list_iterator_next(iterator);

  if (next_frame->is_free == 1 || next_frame->page != page) {
    list_iterator_destroy(iterator);
    return -1;
  }

  int i = list_iterator_index(iterator);
  list_iterator_destroy(iterator);
  return i;
}

int get_next_pid_page(t_list *table, uint32_t pid) {
  t_list_iterator *iterator = list_iterator_create(table);
  frame *next_frame = list_iterator_next(iterator);

  while (next_frame->is_free == 1 || next_frame->pid != pid ||
         !list_iterator_has_next(iterator))
    next_frame = list_iterator_next(iterator);

  if (next_frame->is_free == 1 || next_frame->pid != pid) {
    list_iterator_destroy(iterator);
    return -1;
  }

  list_iterator_destroy(iterator);
  return next_frame->page;
}

int get_free_frames() {
  t_list_iterator *iterator = list_iterator_create(page_table);
  int i = 0;
  while (list_iterator_has_next(iterator)) {
    frame *frame = list_iterator_next(iterator);
    if (frame->is_free)
      i++;
  }
  list_iterator_destroy(iterator);
  return i;
}

uint32_t get_process_size(uint32_t pid) {
  t_list_iterator *iterator = list_iterator_create(page_table);
  int i = 0;
  while (list_iterator_has_next(iterator)) {
    frame *frame = list_iterator_next(iterator);
    if (frame->pid == pid && frame->is_free == 0)
      i++;
  }
  list_iterator_destroy(iterator);
  return i * tam_pagina;
}

void alloc_page(int frame_index, uint32_t pid) {
  frame *frame = list_get(page_table, frame_index);
  frame->is_free = 0;
  frame->pid = pid;
  frame->page = next_page;
  next_page++;
}

void dealloc_page(int frame_index) {
  frame *frame = list_get(page_table, frame_index);
  frame->is_free = 1;
}

bool sort_by_page(void *a, void *b) {
  frame *f_a = (frame *)a;
  frame *f_b = (frame *)b;
  return f_a->page > f_b->page;
}

void expand_process(uint32_t pid, int cant_paginas) {
  for (int i = 0; i < cant_paginas; i++) {
    int frame = get_next_free_frame(page_table);
    alloc_page(frame, pid);
  }
}

void reduce_process(uint32_t pid, int cant_paginas) {
  t_list *sorted_table = list_sorted(page_table, &sort_by_page);
  for (int i = 0; i < cant_paginas; i++) {
    int page = get_next_pid_page(sorted_table, pid);
    int frame = get_frame_from_page(page_table, page);
    dealloc_page(frame);
  }
}

void response_resize_process(packet_t *req, int client_socket) {
  uint32_t pid = packet_read_uint32(req);
  uint32_t size = packet_read_uint32(req);
  uint32_t process_size = get_process_size(pid);

  if (size > process_size) {
    uint32_t size_to_add = size - process_size;
    uint32_t cant_paginas = ceil_div(size_to_add, tam_pagina);

    log_info(logger, "PID: %u - Tamanio Actual: %u - Tamanio a Ampliar %u", pid,
             process_size, size_to_add);

    int free_frames = get_free_frames();
    if (cant_paginas > free_frames) {
      packet_t *res = packet_create(OUT_OF_MEMORY);
      packet_send(res, client_socket);
      packet_destroy(res);
      return;
    }
    expand_process(pid, cant_paginas);
  } else if (size < process_size) {
    uint32_t size_to_reduce = process_size - size;
    int cant_paginas = size_to_reduce / tam_pagina;

    log_info(logger, "PID: %u - Tamanio Actual: %u - Tamanio a Reducir %u", pid,
             process_size, size_to_reduce);

    reduce_process(pid, cant_paginas);
  }

  packet_t *res = status_pack(OK);
  packet_send(res, client_socket);
  packet_destroy(res);
}

void response_free_process(packet_t *req, int client_socket) {
  uint32_t pid = packet_read_uint32(req);
  uint32_t process_size = get_process_size(pid);
  if (process_size != 0) {
    int cant_paginas = process_size / tam_pagina;
    reduce_process(pid, cant_paginas);
  }
  packet_t *res = status_pack(OK);
  packet_send(res, client_socket);
  packet_destroy(res);
}

void response_init_process(packet_t *request, int client_socket) {
  char *path = packet_read_string(request);
  char *full_path = file_concat_path(path_instrucciones, path);
  uint8_t exists = file_exists(full_path);
  free(full_path);
  status_code status_code = exists ? OK : NOT_FOUND;
  packet_t *res = status_pack(status_code);
  packet_send(res, client_socket);
  packet_destroy(res);
}

void response_fetch_instruction(packet_t *request, int client_socket) {
  uint32_t program_counter = packet_read_uint32(request);
  char *instruction_path = packet_read_string(request);

  char *instruction = fetch_instruction(program_counter, instruction_path);
  if (instruction != NULL) {
    log_info(logger, "INSTRUCCION %s - PATH %s - Program Counter: %u",
             instruction, instruction_path, program_counter);
    packet_t *res = packet_create(INSTRUCTION);
    packet_add_string(res, instruction);
    packet_send(res, client_socket);
    free(instruction);
    packet_destroy(res);
  } else {
    packet_t *res = status_pack(END_OF_FILE);
    packet_send(res, client_socket);
    packet_destroy(res);
  }
}

// Validar que la memoria pertenezca al proceso que lee....????
void response_read_dir(packet_t *request, int client_socket) {
  uint32_t address = packet_read_uint32(request);
  uint32_t pid = packet_read_uint32(request);
  uint32_t size = packet_read_uint32(request);
  log_info(logger,
           "PID: %u - Accion: LECTURA - Direccion fisica: %u - Tamanio %u", pid,
           address, size);

  packet_t *res = packet_create(MEMORY_CONTENT);
  for (int i = 0; i < size; i++) {
    uint8_t *aux = user_memory;
    aux += address + i;
    packet_add_uint8(res, *aux);
  }

  packet_send(res, client_socket);
  packet_destroy(res);
}

// Validar que la memoria pertenezca al proceso que escribe....????
void response_write_dir(packet_t *request, int client_socket) {
  uint32_t address = packet_read_uint32(request);
  uint32_t pid = packet_read_uint32(request);
  uint32_t size = packet_read_uint32(request);
  log_info(logger,
           "PID: %u - Accion: ESCRITURA - Direccion fisica: %u - Tamanio %u",
           pid, address, size);

  for (int i = 0; i < size; i++) {
    uint8_t to_write = packet_read_uint8(request);
    uint8_t *aux = user_memory;
    aux += address + i;
    memset(aux, to_write, 1);
  }
}

void *atender_cliente(void *args) {
  int client_socket = *(int *)args;
  packet_t *req = packet_recieve(client_socket);
  usleep(retardo_respuesta * 1000);
  switch (req->type) {
  case INIT_PROCESS:
    response_init_process(req, client_socket);
    break;
  case FETCH_INSTRUCTION:
    response_fetch_instruction(req, client_socket);
    break;
  case READ_DIR:
    response_read_dir(req, client_socket);
    break;
  case WRITE_DIR:
    response_write_dir(req, client_socket);
    break;
  case RESIZE_PROCESS:
    response_resize_process(req, client_socket);
    break;
  case FREE_PROCESS:
    response_free_process(req, client_socket);
    break;
  default:
    break;
  }
  packet_destroy(req);
  connection_close(client_socket);
  free(args);
  return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
  logger = log_create("memoria.log", "MEMORIA", 1, LOG_LEVEL_DEBUG);

  if (argc < 2)
    exit_not_enough_arguments_error(logger);

  config = config_create(argv[1]);
  if (config == NULL)
    exit_enoent_error(logger, argv[1]);

  tam_memoria = config_get_int_value(config, "TAM_MEMORIA");
  tam_pagina = config_get_int_value(config, "TAM_PAGINA");
  frame_count = tam_memoria / tam_pagina;
  retardo_respuesta = config_get_int_value(config, "RETARDO_RESPUESTA");
  path_instrucciones = config_get_string_value(config, "PATH_INSTRUCCIONES");

  puerto_escucha = config_get_string_value(config, "PUERTO_ESCUCHA");

  int server_socket = connection_create_server(puerto_escucha);
  if (server_socket == -1)
    exit_server_connection_error(logger);
  log_info(logger, "Servidor levantado en el puerto %s", puerto_escucha);

  user_memory = malloc(tam_memoria);
  page_table = list_create();

  for (int i = 0; i < frame_count; i++) {
    frame *frame_struct = malloc(sizeof(frame));
    frame_struct->pid = 0;
    frame_struct->is_free = 1;
    frame_struct->page = 0;
    list_add(page_table, frame_struct);
  }

  while (1) {
    int client_socket = connection_accept_client(server_socket);
    if (client_socket == -1)
      continue;
    pthread_t thread;
    int *arg = malloc(sizeof(int));
    *arg = client_socket;
    pthread_create(&thread, NULL, &atender_cliente, arg);
    pthread_detach(thread);
  }

  free(user_memory);
  list_destroy_and_destroy_elements(page_table, &free);
  log_destroy(logger);
  connection_close(server_socket);
  config_destroy(config);
  return EXIT_SUCCESS;
}
