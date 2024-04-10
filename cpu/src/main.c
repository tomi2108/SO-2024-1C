#include <commons/config.h>
#include <commons/log.h>
#include <pthread.h>
#include <utils/connection.h>
#include <utils/packet.h>

t_log *logger;
t_config *config;

void *gestionar_dispatch(void *args) {
  char *puerto_dispatch =
      config_get_string_value(config, "PUERTO_ESCUCHA_DISPATCH");

  int socket_dispatch = connection_create_server(puerto_dispatch);

  connection_close(socket_dispatch);
  return args;
}

void *gestionar_interrupt(void *args) {

  char *puerto_interrumpt =
      config_get_string_value(config, "PUERTO_ESCUCHA_INTERRUPT");
  int socket_interrumpt = connection_create_server(puerto_interrumpt);

  connection_close(socket_interrumpt);
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
  pthread_create(servers[0], NULL, &gestionar_dispatch, NULL);
  pthread_create(servers[1], NULL, &gestionar_interrupt, NULL);

  pthread_join(*servers[0], NULL);
  pthread_join(*servers[1], 0);

  log_destroy(logger);
  config_destroy(config);
  return 0;
}
