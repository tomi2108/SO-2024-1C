#include <commons/collections/list.h>
#include <commons/config.h>
#include <commons/log.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

t_list *page_table;
pthread_mutex_t page_table_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
  uint32_t pid;
  int is_free;
  uint32_t page;
  int frame_number;
} frame;

void print_page_table() {
    pthread_mutex_lock(&page_table_mutex);
    log_info(logger, "Contenido de la tabla de páginas:");
    for (int i = 0; i < list_size(page_table); i++) {
        frame *f = list_get(page_table, i);
        log_info(logger, "Frame %d - PID: %u, Página: %u, is_free: %d", f->frame_number, f->pid, f->page, f->is_free);
    }
    pthread_mutex_unlock(&page_table_mutex);
}

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
  pthread_mutex_lock(&page_table_mutex);
  t_list_iterator *iterator = list_iterator_create(table);

  frame *next_frame = NULL;
  while (list_iterator_has_next(iterator)){
    next_frame = list_iterator_next(iterator);
    if (next_frame->is_free) {
    int index = list_iterator_index(iterator);
    list_iterator_destroy(iterator);
    pthread_mutex_unlock(&page_table_mutex);
    return index;
    }
  }

  list_iterator_destroy(iterator);
  pthread_mutex_unlock(&page_table_mutex);
  return -1;
}

int get_frame_from_page(t_list *table, uint32_t page, uint32_t pid) {
  pthread_mutex_lock(&page_table_mutex);
  //log_debug(logger, "Entrando a get_frame_from_page para PID: %u, Página: %u", pid, page);
  
  if (list_is_empty(table)) {
    log_error(logger, "La tabla de páginas está vacía");
    pthread_mutex_unlock(&page_table_mutex);
    return -1;
  }
  
  int frame_number = -1;
  t_list_iterator *iterator = list_iterator_create(table);

  while (list_iterator_has_next(iterator)) {
    frame *next_frame = list_iterator_next(iterator);
    //log_debug(logger, "Revisando frame: PID: %u, Página: %u, is_free: %d", next_frame->pid, next_frame->page, next_frame->is_free);
    if (next_frame != NULL && !next_frame->is_free && next_frame->page == page && next_frame->pid == pid) {
      frame_number = next_frame -> frame_number;
      log_debug(logger, "Frame encontrado: PID: %u, Página: %u", next_frame->pid, next_frame->page);
      break;
    }
  }
  
  list_iterator_destroy(iterator);
  pthread_mutex_unlock(&page_table_mutex);

  if (frame_number == -1) {
    log_debug(logger, "No se encontró frame para PID: %u, Página: %u", pid, page);
  }

  return frame_number;
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

int get_pages_count(uint32_t pid) { 
  pthread_mutex_lock(&page_table_mutex);
  int count = 0;
  count = get_process_size(pid);
  pthread_mutex_unlock(&page_table_mutex);
  return count; 
  }

void alloc_page(int frame_index, uint32_t pid, uint32_t page) {
  pthread_mutex_lock(&page_table_mutex);

  if(frame_index < 0 || frame_index >= list_size(page_table)){
    pthread_mutex_unlock(&page_table_mutex);
    log_error(logger, "Index de frmae inválido: %d", frame_index);
    return;
  }
  frame *frame = list_get(page_table, frame_index);
  frame->is_free = 0;
  frame->pid = pid;
  frame->page = page;
  log_info(logger, "Asignando frame: %d a PID: %u, Página: %u", frame_index, pid, page);
  pthread_mutex_unlock(&page_table_mutex);

  //print_page_table();
}

void dealloc_page(int frame_index) {
  pthread_mutex_lock(&page_table_mutex);
  if (frame_index < 0 || frame_index >= list_size(page_table)) {
    pthread_mutex_unlock(&page_table_mutex);
    log_error(logger, "Índice de frame inválido: %d", frame_index);
    return;
  }
  frame *frame = list_get(page_table, frame_index);
  if (frame->is_free) {
    log_warning(logger, "El frame %d ya está libre, no se puede liberar nuevamente.", frame_index);
  } else {
      frame->is_free = 1;
      log_info(logger, "Liberando frame: %d, PID: %u, Página: %u", frame_index, frame->pid, frame->page);
      }
  pthread_mutex_unlock(&page_table_mutex);

  //print_page_table();
}

bool sort_by_page(void *a, void *b) {
  frame *f_a = (frame *)a;
  frame *f_b = (frame *)b;
  return f_a->page > f_b->page;
}

void expand_process(uint32_t pid, int cant_paginas) {
  for (int i = 0; i < cant_paginas; i++) {
    int frame = get_next_free_frame(page_table);
    if (frame == -1) {
      log_error(logger, "No hay frames libres disponibles para expandir el proceso PID: %u", pid);
      return;
    }
    int next_page = get_pages_count(pid);
    alloc_page(frame, pid, next_page);
  }
}

void reduce_process(uint32_t pid, int cant_paginas) {
  t_list *sorted_table = list_sorted(page_table, &sort_by_page);
  for (int i = 0; i < cant_paginas; i++) {
    int page = get_next_pid_page(sorted_table, pid);
    int frame = get_frame_from_page(page_table, page, pid);
    dealloc_page(frame);
  }
  list_destroy(sorted_table);
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
  free(path);
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
  free(instruction_path);
}

void response_fetch_frame_number(packet_t *req, int client_socket) {
  uint32_t pid = packet_read_uint32(req);
  uint32_t page_number = packet_read_uint32(req);

  //log_debug(logger, "Buscando frame para PID: %u, Página: %u", pid, page_number);
  
  uint32_t frame_number = get_frame_from_page(page_table, page_number, pid);

  if (frame_number == -1) {
    //log_info(logger, "Frame no encontrado para PID: %u, Página: %u. Asignando nuevo frame", pid, page_number);
    int new_frame_index = get_next_free_frame(page_table);
    if (new_frame_index == -1) {
      log_error(logger, "No hay frames libres disponibles para asignar a PID: %u, Página: %u", pid, page_number);
      packet_t *res = packet_create(ERROR);
      packet_send(res, client_socket);
      packet_destroy(res);
      return;
    }  
    alloc_page(new_frame_index, pid, page_number);
    frame_number = new_frame_index;
  }
  packet_t *res = packet_create(FETCH_FRAME_NUMBER);
  packet_add_uint32(res, frame_number);
  packet_send(res, client_socket);
  packet_destroy(res);
  
}

// Validar que la memoria pertenezca al proceso que lee....????
void response_read_dir(packet_t *request, int client_socket) {
  uint32_t address = packet_read_uint32(request);
  uint32_t pid = packet_read_uint32(request);
  uint32_t size = packet_read_uint32(request);
  log_info(logger,
           "PID: %u - Accion: LECTURA - Direccion fisica: %u - Tamanio %u", pid,
           address, size);
  
  if (address + size > tam_memoria) {
    log_error(logger, "Acceso de memoria fuera de límites.");
    packet_t *res = packet_create(ERROR);
    packet_send(res, client_socket);
    packet_destroy(res);
    return;
  }

  packet_t *res = packet_create(MEMORY_CONTENT);
  for (int i = 0; i < size; i++) {
    uint8_t *aux = user_memory + address + i;
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
  
  if (address + size > tam_memoria) {
    log_error(logger, "Acceso de memoria fuera de límites.");
    packet_t *res = packet_create(ERROR);
    packet_send(res, client_socket);
    packet_destroy(res);
    return;
  }

  uint8_t *data = malloc(size);
  if (data == NULL) {
    log_error(logger, "No se pudo asignar memoria para la escritura.");
    packet_t *res = packet_create(ERROR);
    packet_send(res, client_socket);
    packet_destroy(res);
    return;
  }

  for (uint32_t i = 0; i < size; i++) {
    data[i] = packet_read_uint8(request);
  }

  //pthread_mutex_lock(&memory_mutex); 
  memcpy(user_memory + address, data, size);
  //pthread_mutex_unlock(&memory_mutex);

  free(data);

  packet_t *res = status_pack(OK);
  packet_send(res, client_socket);
  packet_destroy(res);
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
  case FETCH_FRAME_NUMBER:
    response_fetch_frame_number(req, client_socket);
    break;
  case TAMANIO_PAGINA_REQUEST:
    packet_t *res = packet_create(TAMANIO_PAGINA_RESPONSE);
    packet_add_uint8(res, tam_pagina);
    packet_send(res, client_socket);
    packet_destroy(res);
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
  if (user_memory == NULL) {
    log_error(logger, "Error al asignar memoria para user_memory");
    exit(EXIT_FAILURE);
  }
  memset(user_memory, 0, tam_memoria);

  page_table = list_create();
  if (page_table == NULL) {
    log_error(logger, "Error al crear la page_table");
    free(user_memory);
    exit(EXIT_FAILURE);
  }

  for (int i = 0; i < frame_count; i++) {
    frame *frame_struct = malloc(sizeof(frame));
    if (frame_struct == NULL) {
      log_error(logger, "Error al asignar memoria para el frame %d", i);
      exit(EXIT_FAILURE);
    }
    frame_struct->pid = 0;
    frame_struct->is_free = 1;
    frame_struct->page = 0;
    frame_struct->frame_number = i;
    list_add(page_table, frame_struct);
  }

  //print_page_table();

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
