#include <commons/collections/list.h>
#include <commons/config.h>
#include <commons/log.h>
#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/unistd.h>
#include <time.h>
#include <unistd.h>
#include <utils/connection.h>
#include <utils/exit.h>
#include <utils/instruction.h>
#include <utils/packet.h>
#include <utils/status.h>

#define FILE_NAME_MAX_LENGTH 60

t_log *logger;
t_config *config;

char *puerto_escucha;

int tam_memoria;
int tam_pagina;
int cantidad_paginas;
int retardo_respuesta;
char *path_instrucciones;

void *user_memory;
t_list *page_table;

typedef struct {
  uint32_t pid;
  int is_free;
  uint32_t frame;
} page;

char *get_full_path(char *relative_path) {

  char *full_path = malloc(
      sizeof(char) * (1 + strlen(relative_path) + strlen(path_instrucciones)));
  memset(full_path, 0, 1 + strlen(relative_path) + strlen(path_instrucciones));
  strcat(full_path, path_instrucciones);
  strcat(full_path, relative_path);
  return full_path;
}

char *fetch_instruction(uint32_t program_counter, char *instruction_path) {
  char *full_path = get_full_path(instruction_path);

  FILE *file = fopen(full_path, "r");
  free(full_path);

  if (file == NULL)
    exit_enoent_erorr(logger);

  char *line = malloc(FILE_NAME_MAX_LENGTH * sizeof(char));
  int i = 0;
  while (fgets(line, FILE_NAME_MAX_LENGTH, file)) {
    if (i == program_counter) {
      fclose(file);
      return line;
    }
    i++;
  }
  free(line);
  fclose(file);
  return NULL;
}

uint8_t path_exists(char *path) {
  char *full_path = get_full_path(path);
  int exists = access(full_path, F_OK);
  free(full_path);
  return exists == 0;
}

void response_resize_process(packet_t *req, int client_socket) {
  uint32_t pid = packet_read_uint32(req);
  uint32_t size = packet_read_uint32(req);
}

void response_init_process(packet_t *request, int client_socket) {
  char *path = packet_read_string(request);
  uint8_t exists = path_exists(path);
  status_code status_code = exists ? OK : NOT_FOUND;
  packet_t *res = status_pack(status_code);
  packet_send(res, client_socket);
  packet_destroy(res);
}

void response_fetch_instruction(packet_t *request, int client_socket) {
  uint32_t program_counter = packet_read_uint32(request);
  char *instruction_path = packet_read_string(request);

  char *instruction = fetch_instruction(program_counter, instruction_path);
  log_debug(logger, "%s", instruction);
  if (instruction != NULL) {
    packet_t *res = packet_create(INSTRUCTION);
    packet_add_string(res, instruction);
    packet_send(res, client_socket);
    free(instruction);
    packet_destroy(res);
  } else {
    log_debug(logger, "No hay mas instrucciones");
    packet_t *res = status_pack(END_OF_FILE);
    packet_send(res, client_socket);
    packet_destroy(res);
  }
}

void response_read_dir(packet_t *request, int client_socket) {
  uint32_t address = packet_read_uint32(request);
  int frame_number = floor(address / tam_pagina);
  int offset = address - frame_number * tam_pagina;

  uint8_t *aux = user_memory;
  aux += (tam_pagina * frame_number) + offset;
  packet_t *res = packet_create(MEMORY_CONTENT);
  packet_add_uint8(res, *aux);
  packet_send(res, client_socket);
  packet_destroy(res);
}

void response_write_dir(packet_t *request, int client_socket) {
  uint32_t address = packet_read_uint32(request);
  int frame_number = floor(address / tam_pagina);
  int offset = address - frame_number * tam_pagina;

  param_type p;
  packet_read(request, &p, sizeof(param_type));

  if (p == NUMBER) {
    // uint32_t to_write = packet_read_uint32(request);
    // uint8_t first_byte = to_write & 255;
    // uint8_t second_byte = to_write & 65280;
    // uint8_t third_byte = to_write & 16711680;
    // uint8_t fourth_byte = to_write & 4278190080;
    //
    // *aux = first_byte;
    // *(aux + 1) = second_byte;
    // *(aux + 2) = third_byte;
    // *(aux + 3) = fourth_byte;
    //
  } else if (p == STRING) {
    char *to_write = packet_read_string(request);
    for (int i = 0; i < strlen(to_write); i++) {
      uint8_t *aux = user_memory;
      aux += (tam_pagina * frame_number) + offset;
      log_info(logger, "Writing %c to page %d and offset %d", to_write[i],
               frame_number, offset);
      memset(aux, to_write[i], 1);
      if (offset == tam_pagina - 1) {
        offset = 0;
        frame_number++;
      } else
        offset++;
    }
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
    exit_enoent_erorr(logger);

  tam_memoria = config_get_int_value(config, "TAM_MEMORIA");
  tam_pagina = config_get_int_value(config, "TAM_PAGINA");
  cantidad_paginas = tam_memoria / tam_pagina;
  retardo_respuesta = config_get_int_value(config, "RETARDO_RESPUESTA");
  path_instrucciones = config_get_string_value(config, "PATH_INSTRUCCIONES");

  puerto_escucha = config_get_string_value(config, "PUERTO_ESCUCHA");

  int server_socket = connection_create_server(puerto_escucha);
  if (server_socket == -1)
    exit_server_connection_error(logger);
  log_info(logger, "Servidor levantado en el puerto %s", puerto_escucha);

  user_memory = malloc(tam_memoria);
  page_table = list_create();

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
  list_destroy(page_table);
  log_destroy(logger);
  connection_close(server_socket);
  config_destroy(config);
  return EXIT_SUCCESS;
}
