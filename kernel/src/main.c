#include <commons/config.h>
#include <commons/log.h>
#include <stdint.h>
#include <utils/connection.h>
#include <utils/packet.h>

t_log *logger;
t_config *config;

void *gestionar_memoria(void *args) {

  char *puerto_memoria = config_get_string_value(config, "PUERTO_MEMORIA");
  char *ip_memoria = config_get_string_value(config, "IP_MEMORIA");

  int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);

  connection_close(socket_memoria);
  return args;
}

void *gestionar_interfaz_generica(int socket_cliente,
                                  packet_t *paquete_peticion,
                                  uint32_t tiempo_espera) {
  uint32_t nombre_length, tipo_interfaz_length;
  char *nombre = packet_read_string(paquete_peticion, &nombre_length);
  char *tipo_interfaz =
      packet_read_string(paquete_peticion, &tipo_interfaz_length);

  log_info(logger, "Se conecto una interfaz de tipo %s y nombre %s",
           tipo_interfaz, nombre);

  packet_destroy(paquete_peticion);
  packet_t *paquete_respuesta = packet_create(KERNEL);
  packet_add_uint32(paquete_respuesta, tiempo_espera);

  packet_send(paquete_respuesta, socket_cliente);

  packet_destroy(paquete_respuesta);
  connection_close(socket_cliente);
  return NULL;
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

  char *puerto_escucha = config_get_string_value(config, "PUERTO_ESCUCHA");
  int socket_escucha = connection_create_server(puerto_escucha);

  log_info(logger, "Servidor levantado en el puerto %s", puerto_escucha);

  int socket_cliente = connection_accept_client(socket_escucha);
  packet_t *packet = packet_create(0);
  packet_recieve(packet, socket_cliente);

  // if packet->author == IO && tipo_interfaz == generica....
  gestionar_interfaz_generica(socket_cliente, packet, 2000);

  connection_close(socket_escucha);
  log_destroy(logger);
  config_destroy(config);
  return 0;
}
