#include <commons/config.h>
#include <commons/log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <utils/connection.h>
#include <utils/exit.h>
#include <utils/instruction.h>
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

void interfaz_generica(packet_t *res) {
  long tiempo_espera;
  packet_read(res, &tiempo_espera, sizeof(long));
  log_info(logger, "Esperando %ld segundos",
           (tiempo_espera * tiempo_unidad_trabajo_ms) / 1000);
  usleep(tiempo_unidad_trabajo_ms * tiempo_espera * 1000);
}

void interfaz_stdout(packet_t *res) {
  usleep(tiempo_unidad_trabajo_ms * 1000);
  uint32_t address = packet_read_uint32(res);
  uint32_t pid = packet_read_uint32(res);
  uint32_t length = packet_read_uint32(res);

  int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);
  if (socket_memoria == -1)
    exit_client_connection_error(logger);

  packet_t *req = packet_create(READ_DIR);
  packet_add_uint32(req, address);
  packet_add_uint32(req, pid);
  packet_add_uint32(req, length);

  packet_send(req, socket_memoria);
  packet_destroy(req);

  packet_t *res_memoria = packet_recieve(socket_memoria);
  uint8_t memory_content = packet_read_uint8(res_memoria);
  connection_close(socket_memoria);
  packet_destroy(res_memoria);

  log_info(logger, "Se leyo de memoria: %u de la direccion %u", memory_content,
           address);
}

void interfaz_stdin(packet_t *res) {
  uint32_t address = packet_read_uint32(res);
  uint32_t pid = packet_read_uint32(res);
  uint32_t length = packet_read_uint32(res);

  int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);
  if (socket_memoria == -1)
    exit_client_connection_error(logger);

  char *input = ""; // TODO: sanitizar el input de alguna forma... restringir
                    // longitud quizas ?
  scanf("%s", input);
  packet_t *req = packet_create(WRITE_DIR);
  packet_add_uint32(req, pid);
  packet_add_uint32(req, address);
  packet_add_uint32(req, length);

  for (int i = 0; i < length; i++)
    packet_add_uint8(req, input[i]);

  packet_send(req, socket_memoria);
  packet_destroy(req);

  packet_t *res_memoria = packet_recieve(socket_memoria);
  connection_close(socket_memoria);
  uint8_t status = status_unpack(res_memoria);
  packet_destroy(res);

  if (status != OK)
    log_error(logger,
              "No se pudo escribir %s en la direccion %u, la memoria respondio "
              "con un error",
              input, address);
  else
    log_info(logger, "Se escribio %s en la direccion %u", input, address);
}

void interfaz_dialfs(packet_t *res) {}

void request_register_io(int client_socket) {
  if (client_socket == -1)
    exit_client_connection_error(logger);

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

  if (argc < 3)
    exit_not_enough_arguments_error(logger);

  config = config_create(argv[1]);
  if (config == NULL)
    exit_enoent_erorr(logger);

  io_type = config_get_string_value(config, "TIPO_INTERFAZ");
  if (!is_io_type_supported())
    exit_config_field_error(logger, "TIPO_INTERFAZ");

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
    packet_t *res = packet_recieve(socket_kernel);
    if (strcmp(io_type, "generica") == 0) {
      interfaz_generica(res);
    } else if (strcmp(io_type, "stdin")) {
      interfaz_stdin(res);
    } else if (strcmp(io_type, "stdout")) {
      interfaz_stdout(res);
    } else if (strcmp(io_type, "dialfs"))
      interfaz_dialfs(res);
    packet_destroy(res);
  }

  connection_close(socket_kernel);
  log_destroy(logger);
  config_destroy(config);
  return EXIT_SUCCESS;
}
