#include <commons/config.h>
#include <commons/log.h>
#include <pthread.h>
#include <utils/connection.h>
#include <utils/packet.h>
#include <utils/process.h>

t_log *logger;
t_config *config;

void response_exec_process(packet_t*req,int client_socket){
  process_t process = process_unpack(req);
  // ejecutar ciclo de instrucciones con process->path
}


void *server_dispatch(void *args) {
  char *puerto_dispatch =
      config_get_string_value(config, "PUERTO_ESCUCHA_DISPATCH");

  int server_socket= connection_create_server(puerto_dispatch);

  int client_socket = connection_accept_client(server_socket);
  packet_t* req= packet_recieve(client_socket);
switch(req->type){
  case PROCESS:
    response_exec_process(req,client_socket);
    break;
  default:
    break;
}

packet_destroy(req);
connection_close(client_socket);
  connection_close(server_socket);
  return args;
}

void *server_interrupt(void *args) {

  char *puerto_interrupt =
      config_get_string_value(config, "PUERTO_ESCUCHA_INTERRUPT");
  int server_socket= connection_create_server(puerto_interrupt);

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
  }
  int cantidad_entradas_tlb =
      config_get_int_value(config, "CANTIDAD_ENTRADAS_TLB");
  char *algoritmo_tlb = config_get_string_value(config, "ALGORITMO_TLB");

  pthread_t *servers[2];
  pthread_create(servers[0], NULL, &server_dispatch, NULL);
  pthread_create(servers[1], NULL, &server_interrupt, NULL);

  pthread_join(*servers[0], NULL);
  pthread_join(*servers[1], 0);

  log_destroy(logger);
  config_destroy(config);
  return 0;
}
