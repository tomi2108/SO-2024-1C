#include <commons/config.h>
#include <commons/log.h>
#include <utils/connection.h>
#include <utils/packet.h>
#include <utils/person.h>

t_log *logger;
t_config *config;

void *gestionar_escucha(void *args) {

  char *puerto_escucha = config_get_string_value(config, "PUERTO_ESCUCHA");
  int socket_escucha = connection_create_server(puerto_escucha);

  log_info(logger, "Servidor levantado en el puerto %s", puerto_escucha);

  connection_accept_client(socket_escucha);

  connection_close(socket_escucha);
  return args;
}

void *gestionar_memoria(void *args) {

  char *puerto_memoria = config_get_string_value(config, "PUERTO_MEMORIA");
  char *ip_memoria = config_get_string_value(config, "IP_MEMORIA");

  int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);

  connection_close(socket_memoria);
  return args;
}

int main(int argc, char *argv[]) {

  if (argc < 2)
    return 1;

  config = config_create(argv[1]);
  if (config == NULL)
    return 2;

  logger = log_create("kernel.log", "KERNEL", 1, LOG_LEVEL_DEBUG);

  // config conexiones
  char *puerto_cpu_dispatch =
      config_get_string_value(config, "PUERTO_CPU_DISPATCH");
  char *puerto_cpu_interrupt =
      config_get_string_value(config, "PUERTO_CPU_INTERRUPT");
  char *ip_cpu = config_get_string_value(config, "IP_CPU");

  // confgi del modulo
  char *algoritmo_planificacion =
      config_get_string_value(config, "ALGORITMO_PLANIFICACION");
  int quantum = config_get_int_value(config, "QUANTUM");
  int grado_multiprogramacion =
      config_get_int_value(config, "GRADO_MULTIPROGRAMACION");
  char **instancias_recursos =
      config_get_array_value(config, "INSTANCIAS_RECURSOS");
  char **recursos = config_get_array_value(config, "RECURSOS");

  log_destroy(logger);
  config_destroy(config);
  return 0;
}
