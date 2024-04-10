#include <commons/config.h>
#include <commons/log.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <utils/connection.h>
#include <utils/packet.h>
#include <utils/status.h>

t_log *logger;
t_config *config;

void request_init_process(char *path) {
  char *puerto_memoria = config_get_string_value(config, "PUERTO_MEMORIA");
  char *ip_memoria = config_get_string_value(config, "IP_MEMORIA");

  int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);

  packet_t *packet = packet_create(INIT_PROCESS);
  packet_add_string(packet, strlen(path), path);
  packet_send(packet, socket_memoria);
  packet_destroy(packet);

  packet_t *res = packet_recieve(socket_memoria);
  uint8_t status_code = status_read_packet(res);
  if (status_code == NOT_FOUND) {
    log_error(logger, "El archivo %s no existe", path);
  } else if (status_code == OK) {
    // agregar el proceso a la cola de new
  }

  connection_close(socket_memoria);
}

void response_register_io(packet_t *request, int client_socket) {
  char *nombre = packet_read_string(request, NULL);
  char *tipo_interfaz = packet_read_string(request, NULL);

  log_info(logger, "Se conecto una interfaz de tipo %s y nombre %s",
           tipo_interfaz, nombre);

  packet_destroy(request);

  // guardar el socket de la I/O para responderle cuando sea necesario
}

void *atender_cliente(void *args) {
  int client_socket = *(int *)args;
  packet_t *request = packet_recieve(client_socket);

  switch (request->type) {
  case REGISTER_IO:
    response_register_io(request, client_socket);
    break;
  default:
    break;
  }

  connection_close(client_socket);
  free(args);
}

int main(int argc, char *argv[]) {

  logger = log_create("kernel.log", "KERNEL", 1, LOG_LEVEL_DEBUG);

  if (argc < 2) {
    log_error(logger, "Especificar archivo de configuracion");
    return 1;
  }

  config = config_create(argv[1]);
  if (config == NULL) {
    log_error(logger, "Error al crear la configuracion");
  }

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

  char *puerto_escucha = config_get_string_value(config, "PUERTO_ESCUCHA");
  int server_socket = connection_create_server(puerto_escucha);

  log_info(logger, "Servidor levantado en el puerto %s", puerto_escucha);

  while (1) {
    int client_socket = connection_accept_client(server_socket);
    pthread_t *thread;
    int *arg = malloc(sizeof(int));
    *arg = client_socket;
    pthread_create(thread, NULL, &atender_cliente, arg);
    pthread_detach(*thread);
  }

  connection_close(server_socket);
  log_destroy(logger);
  config_destroy(config);
  return 0;
}
