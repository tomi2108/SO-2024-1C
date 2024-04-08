#include <commons/collections/list.h>
#include <commons/config.h>
#include <commons/log.h>
#include <pthread.h>
#include <utils/connection.h>
#include <utils/instruction.h>
#include <utils/packet.h>

t_log *logger;
t_config *config;

struct thread_args {
  packet_t *packet;
  int socket;
};

instruction_t fetch_instruction(uint32_t program_counter,
                                char *instruction_path) {
  instruction_t ins;
  ins.params = list_create();
  return ins;
}

void *atender_cpu(void *args) {
  struct thread_args *th_args = (struct thread_args *)args;
  packet_t *packet = th_args->packet;
  int client_socket = th_args->socket;

  // if packet->type == fetch_instruccion
  uint32_t program_counter = packet_read_uint32(packet);
  char *instruction_path = packet_read_string(packet, NULL);
  packet_destroy(packet);

  instruction_t instruction =
      fetch_instruction(program_counter, instruction_path);

  packet_t *res = packet_create(MEMORY);

  instruction_pack(res, instruction);
  list_destroy(instruction.params);

  packet_send(res, client_socket);
  packet_destroy(res);

  connection_close(client_socket);
  free(th_args);
  return 0;
}

void *atender_kernel(void *args) {
  struct thread_args *th_args = (struct thread_args *)args;
  packet_t *packet = th_args->packet;
  int client_socket = th_args->socket;

  packet_destroy(packet);
  connection_close(client_socket);
  free(th_args);
  return 0;
}

void *atender_io(void *args) {
  struct thread_args *th_args = (struct thread_args *)args;
  packet_t *packet = th_args->packet;
  int client_socket = th_args->socket;

  packet_destroy(packet);
  connection_close(client_socket);
  free(th_args);
  return 0;
}

int main(int argc, char *argv[]) {

  if (argc < 2)
    return 1;

  config = config_create(argv[1]);
  if (config == NULL)
    return 2;

  logger = log_create("memoria.log", "MEMORIA", 1, LOG_LEVEL_DEBUG);

  int tam_memoria = config_get_int_value(config, "TAM_MEMORIA");
  int tam_pagina = config_get_int_value(config, "TAM_PAGINA");
  char *PATH_INSTRUCCIONES =
      config_get_string_value(config, "PATH_INSTRUCCIONES");
  int cantidad_entradas_tlb = config_get_int_value(config, "RETARDO_RESPUESTA");

  char *puerto_escucha = config_get_string_value(config, "PUERTO_ESCUCHA");
  int server_socket = connection_create_server(puerto_escucha);
  log_debug(logger, "Servidor levantado en el puerto %s", puerto_escucha);

  while (1) {
    int client_socket = connection_accept_client(server_socket);
    packet_t *packet = packet_create(0);
    packet_recieve(packet, client_socket);

    struct thread_args *args = malloc(sizeof(struct thread_args));
    args->packet = packet_dup(packet);
    args->socket = client_socket;
    packet_destroy(packet);

    pthread_t *thread_id;
    switch (packet->author) {
    case CPU: {
      pthread_create(thread_id, NULL, &atender_cpu, args);
      pthread_detach(*thread_id);
      break;
    }
    case KERNEL: {
      pthread_create(thread_id, NULL, &atender_kernel, args);
      pthread_detach(*thread_id);
      break;
    }
    case IO: {
      pthread_create(thread_id, NULL, &atender_io, args);
      pthread_detach(*thread_id);
      break;
    }
    default:
      break;
    }
  }

  log_destroy(logger);
  config_destroy(config);
  return 0;
}
