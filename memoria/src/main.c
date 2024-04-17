#include <commons/collections/list.h>
#include <commons/config.h>
#include <commons/log.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/unistd.h>
#include <unistd.h>
#include <utils/connection.h>
#include <utils/packet.h>
#include <utils/status.h>

t_log *logger;
t_config *config;

char *puerto_escucha;

int tam_memoria;
int tam_pagina;
int retardo_respuesta;
char *path_instrucciones;

char *fetch_instruction(uint32_t program_counter, char *instruction_path) {
  return "JNZ BX 9";
}

uint8_t path_exists(char *path) {
  char full_path[1 + strlen(path) + strlen(path_instrucciones)];
  memset(full_path, 0, 1 + strlen(path) + strlen(path_instrucciones));
  strcat(full_path, path_instrucciones);
  strcat(full_path, path);
  int exists = access(full_path, F_OK);
  return exists == 0;
}

void response_init_process(packet_t *request, int client_socket) {
  char *path = packet_read_string(request);
  uint8_t exists = path_exists(path);
  uint8_t status_code = exists ? OK : NOT_FOUND;
  packet_t *res = status_create_packet(status_code);
  packet_send(res, client_socket);
  packet_destroy(res);
}

void response_fetch_instruction(packet_t *request, int client_socket) {
  uint32_t program_counter = packet_read_uint32(request);
  char *instruction_path = packet_read_string(request);

  char *instruction = fetch_instruction(program_counter, instruction_path);

  packet_t *res = packet_create(INSTRUCTION);
  packet_add_string(res, instruction);
  packet_send(res, client_socket);
  packet_destroy(res);
}

void response_read_dir(packet_t *request, int client_socket) {}
void response_write_dir(packet_t *request, int client_socket) {}

void *atender_cliente(void *args) {
  int client_socket = *(int *)args;
  packet_t *req = packet_recieve(client_socket);
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
  return 0;
}

int main(int argc, char *argv[]) {

  logger = log_create("memoria.log", "MEMORIA", 1, LOG_LEVEL_DEBUG);

  if (argc < 2) {
    log_error(logger, "Especificar archivo de configuracion");
    return 1;
  }

  config = config_create(argv[1]);
  if (config == NULL) {
    log_error(logger, "Error al crear la configuracion");
    return 2;
  }

  tam_memoria = config_get_int_value(config, "TAM_MEMORIA");
  tam_pagina = config_get_int_value(config, "TAM_PAGINA");
  retardo_respuesta = config_get_int_value(config, "RETARDO_RESPUESTA");
  path_instrucciones = config_get_string_value(config, "PATH_INSTRUCCIONES");

  puerto_escucha = config_get_string_value(config, "PUERTO_ESCUCHA");

  int server_socket = connection_create_server(puerto_escucha);
  if (server_socket == -1) {
    log_error(logger, "Imposible levantar servidor");
    return 3;
  }
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
  return 0;
}
