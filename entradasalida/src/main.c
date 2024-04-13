#include <commons/config.h>
#include <commons/log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <utils/connection.h>
#include <utils/packet.h>
#include <utils/status.h>

t_log *logger;
t_config *config;

int socket_kernel;
int socket_memoria;

char *name;
char *io_type;

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

  packet_t *req = packet_create(READ_DIR);
  packet_add_uint32(req, direccion_fisica);
  packet_send(req, socket_memoria);
  packet_destroy(req);

  packet_t *res = packet_recieve(socket_memoria);
  uint32_t memory_content = packet_read_uint32(res);
  packet_destroy(res);

  sleep(tiempo_unidad_trabajo_ms);
  log_info(logger, "%u", memory_content);
}

// TODO: se asume que la direccion fisica sera uint32_t verificar cuando se
// realize el modulo memoria Probablemente agregar al paquete de req que se
// intenta escribir la direccion con un codigo_op correspondiente se asume que
// la memoria responde con uint32 (codigo OK or ERR ??) verificar cuando se
// realize el modulo memoria tambien se asume que la memoria puede procesar la
// escritura de un char*
void interfaz_stdin(uint32_t direccion_fisica) {
  char *input; // TODO: sanitizar el input de alguna forma... restringir
               // longitud quizas ?

  scanf("%s", input);
  packet_t *req = packet_create(WRITE_DIR);
  packet_add_string(req, input);
  packet_send(req, socket_memoria);
  packet_destroy(req);

  packet_t *res = packet_recieve(socket_memoria);
  uint8_t status = status_read_packet(res);
  packet_destroy(res);

  if (status != OK)
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

void request_register_io() {

  packet_t *request = packet_create(REGISTER_IO);

  packet_add_string(request, name);
  packet_add_string(request, io_type);
  packet_send(request, socket_kernel);
  packet_destroy(request);

  if (strcmp(io_type, "generica") != 0) {
    char *ip_memoria = config_get_string_value(config, "IP_MEMORIA");
    char *puerto_memoria = config_get_string_value(config, "PUERTO_MEMORIA");
    socket_memoria = connection_create_client(ip_memoria, puerto_memoria);
  }

  while (1) {
    packet_t *res = packet_recieve(socket_kernel);
    if (res == NULL)
      break;
    if (strcmp(io_type, "generica") == 0) {
      uint32_t tiempo_espera = packet_read_uint32(res);
      interfaz_generica(tiempo_espera);
    } else if (strcmp(io_type, "stdin")) {
      uint32_t direccion = packet_read_uint32(res);
      interfaz_stdin(direccion);
    } else if (strcmp(io_type, "stdout")) {
      uint32_t direccion = packet_read_uint32(res);
      interfaz_stdout(direccion);
    } else if (strcmp(io_type, "dialfs"))
      interfaz_dialfs();
  }
  connection_close(socket_memoria);
  connection_close(socket_kernel);
}

uint8_t is_io_type_supported() {
  return strcmp(io_type, "generica") == 0 || strcmp(io_type, "stdin") == 0 ||
         strcmp(io_type, "stdout") == 0 || strcmp(io_type, "dialfs") == 0;
}

int main(int argc, char *argv[]) {

  logger =
      log_create("entradasalida.log", "ENTRADA/SALIDA", 1, LOG_LEVEL_DEBUG);

  if (argc < 3) {
    log_error(logger, "Especificar archivo de configuracion y nombre de la "
                      "interfaz en ese orden");
    return 1;
  }

  config = config_create(argv[1]);
  if (config == NULL) {
    log_error(logger, "Error al crear la configuarcion");
    return 2;
  }

  io_type = config_get_string_value(config, "TIPO_INTERFAZ");
  if (!is_io_type_supported()) {
    log_error(logger, "Interfaz de tipo %s no soportada", io_type);
    return 3;
  }

  // sanitizar input...?
  name = strdup(argv[2]);

  char *ip_kernel = config_get_string_value(config, "IP_KERNEL");
  char *puerto_kernel = config_get_string_value(config, "PUERTO_KERNEL");

  socket_kernel = connection_create_client(ip_kernel, puerto_kernel);
  if(socket_kernel==-1){
    log_error(logger,"Imposible crear la conexion al kernel");
    return 4;
  }

  request_register_io();

  log_destroy(logger);
  config_destroy(config);
  return 0;
}
