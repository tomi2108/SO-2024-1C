#include <commons/config.h>
#include <commons/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <utils/connection.h>

t_log *logger;
t_config *config;

void *gestionar_kernel(void *args) {

  char *ip_kernel = config_get_string_value(config, "IP_KERNEL");
  char *puerto_kernel = config_get_string_value(config, "PUERTO_KERNEL");

  int socket_kernel = connection_create_client(ip_kernel, puerto_kernel);

  connection_close(socket_kernel);
  return args;
}

void *gestionar_memoria(void *args) {

  char *ip_memoria = config_get_string_value(config, "IP_MEMORIA");
  char *puerto_memoria = config_get_string_value(config, "PUERTO_MEMORIA");

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

  logger =
      log_create("entradasalida.log", "ENTRADA/SALIDA", 1, LOG_LEVEL_DEBUG);

  // config del modulo
  char *path_base_dialfs = config_get_string_value(config, "PATH_BASE_DIALFS");
  int block_size = config_get_int_value(config, "BLOCK_SIZE");
  int block_count = config_get_int_value(config, "BLOCK_COUNT");
  char *tipo_interfaz = config_get_string_value(config, "TIPO_INTERFAZ");
  int tiempo_unidad_trabajo_ms =
      config_get_int_value(config, "TIEMPO_UNIDAD_TRABAJO");

  log_destroy(logger);
  config_destroy(config);
  return 0;
}
