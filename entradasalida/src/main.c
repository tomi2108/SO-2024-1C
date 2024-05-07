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

void interfaz_generica(packet_t *res, int socket_kernel) {
  uint32_t tiempo_espera = packet_read_uint32(res);
  log_info(logger, "Esperando %u segundos",
           (tiempo_espera * tiempo_unidad_trabajo_ms) / 1000);
  usleep(tiempo_unidad_trabajo_ms * tiempo_espera * 1000);
  packet_t *res_kernel = status_pack(OK);
  packet_send(res_kernel, socket_kernel);
  packet_destroy(res_kernel);
}

void interfaz_stdout(packet_t *res, int socket_kernel) {
  usleep(tiempo_unidad_trabajo_ms * 1000);
  uint32_t address = packet_read_uint32(res);
  uint32_t pid = packet_read_uint32(res);
  uint32_t size = packet_read_uint32(res);

  int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);
  if (socket_memoria == -1)
    exit_client_connection_error(logger);

  packet_t *req = packet_create(READ_DIR);
  packet_add_uint32(req, address);
  packet_add_uint32(req, pid);
  packet_add_uint32(req, size);

  packet_send(req, socket_memoria);
  packet_destroy(req);

  packet_t *res_memoria = packet_recieve(socket_memoria);
  uint8_t *memory_content = malloc(size + 1);
  memset(memory_content, 0, size + 1);
  for (int i = 0; i < size; i++) {
    uint8_t byte = packet_read_uint8(req);
    *(memory_content + i) = byte;
  }

  connection_close(socket_memoria);
  packet_destroy(res_memoria);

  packet_t *res_kernel = status_pack(OK);
  packet_send(res_kernel, socket_kernel);
  packet_destroy(res_kernel);

  log_info(logger, "Se leyo de memoria: %s de la direccion %u", memory_content,
           address);
  free(memory_content);
}

void interfaz_stdin(packet_t *res, int socket_kernel) {
  uint32_t address = packet_read_uint32(res);
  uint32_t pid = packet_read_uint32(res);
  uint32_t size = packet_read_uint32(res);

  int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);
  if (socket_memoria == -1)
    exit_client_connection_error(logger);

  log_info(logger, "Ingrese string a guardar en memoria");
  char *input = NULL;
  size_t length = 0;
  length = getline(&input, &length, stdin);
  input[length - 1] = '\0';

  packet_t *req = packet_create(WRITE_DIR);
  packet_add_uint32(req, address);
  packet_add_uint32(req, pid);
  packet_add_uint32(req, size);

  for (int i = 0; i < size; i++)
    packet_add_uint8(req, *((uint8_t *)input + i));

  packet_send(req, socket_memoria);
  packet_destroy(req);

  packet_t *res_kernel = status_pack(OK);
  packet_send(res_kernel, socket_kernel);
  packet_destroy(res_kernel);

  log_info(logger, "Se escribio %s en la direccion %u", input, address);
}

void interfaz_dialfs(packet_t *res, int socket_kernel) {

  // una vez que se procesa el paquete del kernel y se opera...
  packet_t *res_kernel = status_pack(OK);
  packet_send(res_kernel, socket_kernel);
  packet_destroy(res_kernel);
}

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
    exit_enoent_error(logger, argv[1]);

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
      interfaz_generica(res, socket_kernel);
    } else if (strcmp(io_type, "stdin") == 0) {
      interfaz_stdin(res, socket_kernel);
    } else if (strcmp(io_type, "stdout") == 0) {
      interfaz_stdout(res, socket_kernel);
    } else if (strcmp(io_type, "dialfs") == 0)
      interfaz_dialfs(res, socket_kernel);
    packet_destroy(res);
  }

  connection_close(socket_kernel);
  log_destroy(logger);
  config_destroy(config);
  return EXIT_SUCCESS;
}
