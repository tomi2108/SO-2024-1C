#include <commons/config.h>
#include <commons/log.h>
#include <pthread.h>
#include <utils/connection.h>
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

void response_exec_process(packet_t *req, int client_socket) {
  process_t process = process_unpack(req);
  // ejecutar ciclo de instrucciones con process->path
}

void *server_dispatch(void *args) {

  int server_socket = connection_create_server(puerto_dispatch);
  if (server_socket == -1) {
    log_error(logger, "Imposible crear el servidor dispatch");
    exit(4);
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

void *server_interrupt(void *args) {

  int server_socket = connection_create_server(puerto_interrupt);

  if (server_socket == -1) {
    log_error(logger, "Imposible crear el servidor interrupt");
    exit(5);
  }

  log_info(logger, "Servidor interrupt levantado en el puerto %s",
           puerto_interrupt);
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

  int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);
  if (socket_memoria == -1)
    log_error(logger, "Imposible crear la conexion a la memoria");
  // por ahora
  connection_close(socket_memoria);

  cantidad_entradas_tlb = config_get_int_value(config, "CANTIDAD_ENTRADAS_TLB");
  algoritmo_tlb = config_get_string_value(config, "ALGORITMO_TLB");

  pthread_t servers[2];
  pthread_create(&servers[0], NULL, &server_dispatch, NULL);
  pthread_create(&servers[1], NULL, &server_interrupt, NULL);

  pthread_join(servers[0], NULL);
  pthread_join(servers[1], 0);

  log_destroy(logger);
  config_destroy(config);
  return 0;
}
