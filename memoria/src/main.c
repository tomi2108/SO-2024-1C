#include <commons/collections/list.h>
#include <commons/config.h>
#include <commons/log.h>
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
#include <utils/packet.h>
#include <utils/status.h>

#define FILE_NAME_MAX_LENGTH 60

t_log *logger;
t_config *config;

char *puerto_escucha;

int tam_memoria;
int tam_pagina;
int retardo_respuesta;
char *path_instrucciones;

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
  log_info(logger, "INSTRUCCION %s - PATH %s - Program Counter: %u",
           instruction, instruction_path, program_counter);
  if (instruction != NULL) {
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

void response_read_dir(packet_t *request, int client_socket) {}
void response_write_dir(packet_t *request, int client_socket) {}

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
  retardo_respuesta = config_get_int_value(config, "RETARDO_RESPUESTA");
  path_instrucciones = config_get_string_value(config, "PATH_INSTRUCCIONES");

  puerto_escucha = config_get_string_value(config, "PUERTO_ESCUCHA");

  int server_socket = connection_create_server(puerto_escucha);
  if (server_socket == -1)
    exit_server_connection_error(logger);
  log_info(logger, "Servidor levantado en el puerto %s", puerto_escucha);

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

  log_destroy(logger);
  connection_close(server_socket);
  config_destroy(config);
  return EXIT_SUCCESS;
}
