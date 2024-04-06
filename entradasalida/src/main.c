#include <commons/config.h>
#include <commons/log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <utils/connection.h>
#include <utils/packet.h>

t_log *logger;
t_config *config;

void interfaz_generica(uint32_t tiempo_espera) {
  int tiempo_unidad_trabajo_ms =
      config_get_int_value(config, "TIEMPO_UNIDAD_TRABAJO");
  log_debug(logger, "Esperando %d segundos",
            tiempo_espera * tiempo_unidad_trabajo_ms / 1000);
  sleep(tiempo_unidad_trabajo_ms * tiempo_espera);
}

// TODO: se asume que la direccion fisica sera uint32_t verificar cuando se
// realize el modulo memoria Probablemente agregar al paquete de req que se
// intenta leer la direccion con un codigo_op correspondiente se asume que la
// memoria responde con uint32 (el contenido de la direccion) verificar cuando
// se realize el modulo memoria
void interfaz_stdout(uint32_t direccion_fisica) {
  int tiempo_unidad_trabajo_ms =
      config_get_int_value(config, "TIEMPO_UNIDAD_TRABAJO");
  char *ip_memoria = config_get_string_value(config, "IP_MEMORIA");
  char *puerto_memoria = config_get_string_value(config, "PUERTO_MEMORIA");

  int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);

  packet_t *packet = packet_create(IO);
  packet_add_uint32(packet, direccion_fisica);
  packet_send(packet, socket_memoria);
  packet_destroy(packet);

  packet_t *packet_res = packet_create(0);
  packet_recieve(packet_res, socket_memoria);
  uint32_t res = packet_read_uint32(packet_res);
  packet_destroy(packet_res);

  sleep(tiempo_unidad_trabajo_ms);
  log_info(logger, "%u", res);

  connection_close(socket_memoria);
}
// TODO: se asume que la direccion fisica sera uint32_t verificar cuando se
// realize el modulo memoria Probablemente agregar al paquete de req que se
// intenta escribir la direccion con un codigo_op correspondiente se asume que
// la memoria responde con uint32 (codigo OK or ERR ??) verificar cuando se
// realize el modulo memoria tambien se asume que la memoria puede procesar la
// escritura de un char*
void interfaz_stdin(uint32_t direccion_fisica) {
  char *ip_memoria = config_get_string_value(config, "IP_MEMORIA");
  char *puerto_memoria = config_get_string_value(config, "PUERTO_MEMORIA");

  int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);

  char *input;
  // TODO: sanitizar el input de alguna forma... restringir longitud quizas ?
  scanf("%s", input);
  packet_t *packet = packet_create(IO);
  packet_add_string(packet, strlen(input), input);
  packet_send(packet, socket_memoria);
  packet_destroy(packet);

  packet_t *packet_res = packet_create(0);
  packet_recieve(packet_res, socket_memoria);
  connection_close(socket_memoria);
  uint32_t res = packet_read_uint32(packet_res);
  packet_destroy(packet_res);

  if (res == 1)
    log_error(logger,
              "No se pudo escribir %s en la direccion %u, la memoria respondio "
              "con un error",
              input, direccion_fisica);
  else
    log_info(logger, "Se escribio %s en la direccion %u", input,
             direccion_fisica);
}
void interfaz_dialfs() {
  char *path_base_dialfs = config_get_string_value(config, "PATH_BASE_DIALFS");
  int block_size = config_get_int_value(config, "BLOCK_SIZE");
  int block_count = config_get_int_value(config, "BLOCK_COUNT");
}

int main(int argc, char *argv[]) {

  if (argc < 2)
    return 1;

  config = config_create(argv[1]);
  if (config == NULL)
    return 2;

  logger =
      log_create("entradasalida.log", "ENTRADA/SALIDA", 1, LOG_LEVEL_DEBUG);

  char *tipo_interfaz = config_get_string_value(config, "TIPO_INTERFAZ");
  char *ip_kernel = config_get_string_value(config, "IP_KERNEL");
  char *puerto_kernel = config_get_string_value(config, "PUERTO_KERNEL");

  int socket_kernel = connection_create_client(ip_kernel, puerto_kernel);

  char *nombre = strdup(argv[2]);

  packet_t *paquete_identificador = packet_create(IO);
  packet_add_string(paquete_identificador, strlen(nombre), nombre);
  packet_add_string(paquete_identificador, strlen(tipo_interfaz),
                    tipo_interfaz);
  packet_send(paquete_identificador, socket_kernel);
  packet_destroy(paquete_identificador);

  packet_t *paquete_respuesta = packet_create(0);
  packet_recieve(paquete_respuesta, socket_kernel);

  if (strcmp(tipo_interfaz, "generica") == 0) {
    uint32_t tiempo_espera = packet_read_uint32(paquete_respuesta);
    interfaz_generica(tiempo_espera);
  } else if (strcmp(tipo_interfaz, "stdin")) {
    uint32_t direccion = packet_read_uint32(paquete_respuesta);
    interfaz_stdin(direccion);
  } else if (strcmp(tipo_interfaz, "stdout")) {
    uint32_t direccion = packet_read_uint32(paquete_respuesta);
    interfaz_stdout(direccion);
  } else if (strcmp(tipo_interfaz, "dialfs"))
    interfaz_dialfs();
  else
    log_error(logger, "Interfaz de tipo %s no soportada", tipo_interfaz);

  packet_destroy(paquete_respuesta);
  connection_close(socket_kernel);
  log_destroy(logger);
  config_destroy(config);
  return 0;
}
