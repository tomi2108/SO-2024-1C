#include <commons/collections/list.h>
#include <commons/config.h>
#include <commons/log.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/unistd.h>
#include <unistd.h>
#include <utils/connection.h>
#include <utils/instruction.h>
#include <utils/packet.h>
#include <utils/status.h>

t_log *logger;
t_config *config;

instruction_t fetch_instruction(uint32_t program_counter,
                                char *instruction_path) {
  instruction_t ins;
  ins.params = list_create();
  return ins;
}

uint8_t path_exists(char *path) {
  char *PATH_INSTRUCCIONES =
      config_get_string_value(config, "PATH_INSTRUCCIONES");
  char *full_path =
      malloc((1 + strlen(path) + strlen(PATH_INSTRUCCIONES)) * sizeof(char));
  strcat(full_path, PATH_INSTRUCCIONES);
  strcat(full_path, path);
  return access(full_path, F_OK) == 0;
}

void response_init_process(packet_t *request, int client_socket) {
  char *path = packet_read_string(request, NULL);
  packet_destroy(request);

  uint8_t exists = path_exists(path);
  uint8_t status_code = exists ? OK : NOT_FOUND;
  packet_t *res = status_create_packet(status_code);
  packet_send(res, client_socket);
  packet_destroy(res);
}

void response_fetch_instruction(packet_t *request, int client_socket) {
  uint32_t program_counter = packet_read_uint32(request);
  char *instruction_path = packet_read_string(request, NULL);
  packet_destroy(request);

  instruction_t instruction =
      fetch_instruction(program_counter, instruction_path);

  packet_t *res = instruction_pack(instruction);
  list_destroy(instruction.params);
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

  connection_close(client_socket);
  free(args);
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
  }

  int tam_memoria = config_get_int_value(config, "TAM_MEMORIA");
  int tam_pagina = config_get_int_value(config, "TAM_PAGINA");
  int cantidad_entradas_tlb = config_get_int_value(config, "RETARDO_RESPUESTA");

  char *puerto_escucha = config_get_string_value(config, "PUERTO_ESCUCHA");
  int server_socket = connection_create_server(puerto_escucha);
  log_debug(logger, "Servidor levantado en el puerto %s", puerto_escucha);

  while (1) {
    int client_socket = connection_accept_client(server_socket);
    pthread_t *thread;
    int *arg = malloc(sizeof(int));
    *arg = client_socket;
    pthread_create(thread, NULL, &atender_cliente, arg);
    pthread_detach(*thread);
  }

  log_destroy(logger);
  config_destroy(config);
  return 0;
}
