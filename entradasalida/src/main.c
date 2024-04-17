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

char *name;
char *io_type;
int tiempo_unidad_trabajo_ms;

char *ip_kernel;
char *puerto_kernel;

char *ip_memoria;
char *puerto_memoria;

char *path_base_dialfs;
int block_size;
int block_count;

void interfaz_generica(long tiempo_espera) {
  log_info(logger, "Esperando %ld segundos",
           (tiempo_espera * tiempo_unidad_trabajo_ms) / 1000);
  sleep((tiempo_unidad_trabajo_ms * tiempo_espera) / 1000);
}

// TODO: se asume que la direccion fisica sera uint32_t verificar cuando se
// realize el modulo memoria Probablemente agregar al paquete de req que se
// intenta leer la direccion con un codigo_op correspondiente se asume que la
// memoria responde con uint32 (el contenido de la direccion) verificar cuando
// se realize el modulo memoria
void interfaz_stdout(uint32_t direccion_fisica) {

  int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);
  if (socket_memoria == -1) {
    log_error(logger, "Imposible conectarse con la memoria");
    exit(4);
  }

  packet_t *req = packet_create(READ_DIR);
  packet_add_uint32(req, direccion_fisica);
  packet_send(req, socket_memoria);
  packet_destroy(req);

  packet_t *res = packet_recieve(socket_memoria);
  connection_close(socket_memoria);
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

  int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);
  if (socket_memoria == -1) {
    log_error(logger, "Imposible conectarse con la memoria");
    exit(4);
  }

  char *input = ""; // TODO: sanitizar el input de alguna forma... restringir
                    // longitud quizas ?

  scanf("%s", input);
  packet_t *req = packet_create(WRITE_DIR);
  packet_add_string(req, input);
  packet_send(req, socket_memoria);
  packet_destroy(req);

  packet_t *res = packet_recieve(socket_memoria);
  connection_close(socket_memoria);
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

void interfaz_dialfs(void) {}

void request_register_io(int client_socket) {
  if (client_socket == -1) {
    log_error(logger, "Imposible crear la conexion al kernel");
    exit(5);
  }

  packet_t *request = packet_create(REGISTER_IO);

  packet_add_string(request, name);
  packet_add_string(request, io_type);
  packet_send(request, client_socket);
  packet_destroy(request);
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

  ip_kernel = config_get_string_value(config, "IP_KERNEL");
  puerto_kernel = config_get_string_value(config, "PUERTO_KERNEL");

  ip_memoria = config_get_string_value(config, "IP_MEMORIA");
  puerto_memoria = config_get_string_value(config, "PUERTO_MEMORIA");

  tiempo_unidad_trabajo_ms =
      config_get_int_value(config, "TIEMPO_UNIDAD_TRABAJO");

  path_base_dialfs = config_get_string_value(config, "PATH_BASE_DIALFS");
  block_size = config_get_int_value(config, "BLOCK_SIZE");
  block_count = config_get_int_value(config, "BLOCK_COUNT");

  int socket_kernel = connection_create_client(ip_kernel, puerto_kernel);
  request_register_io(socket_kernel);

  while (1) {
    log_debug(logger, "Esperando instruccion del kernel");
    packet_t *res = packet_recieve(socket_kernel);
    if (strcmp(io_type, "generica") == 0) {
      long tiempo_espera;
      packet_read(res, &tiempo_espera, sizeof(long));
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

  connection_close(socket_kernel);
  log_destroy(logger);
  config_destroy(config);
  return 0;
}
