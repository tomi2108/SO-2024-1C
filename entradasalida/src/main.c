#include <commons/bitarray.h>
#include <commons/config.h>
#include <commons/log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <utils/connection.h>
#include <utils/exit.h>
#include <utils/file.h>
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

char *parse_file_name(char *file_name) {
  return file_concat_path(path_base_dialfs, file_name);
}

void destroy_bitarray_bitmap(t_bitarray *bitarray) {
  free(bitarray->bitarray);
  bitarray_destroy(bitarray);
}

t_bitarray *get_bitarray_bitmap() {
  char *bitmap_path = parse_file_name("/bitmap.dat");
  char *buffer = 0;
  long length;
  FILE *bitmap_file = fopen(bitmap_path, "rb");

  fseek(bitmap_file, 0, SEEK_END);
  length = ftell(bitmap_file);
  fseek(bitmap_file, 0, SEEK_SET);

  buffer = malloc((length + 1) * sizeof(char));
  fread(buffer, sizeof(char), length, bitmap_file);

  fclose(bitmap_file);
  buffer[length] = '\0';

  return bitarray_create_with_mode(buffer, block_count, MSB_FIRST);
}

void set_bitarray_bitmap(t_bitarray *bitarray) {
  char *bitmap_path = parse_file_name("/bitmap.dat");
  size_t size = bitarray_get_max_bit(bitarray);

  FILE *bitmap_file = fopen(bitmap_path, "wb");
  fwrite(bitarray->bitarray, sizeof(char), size / 8, bitmap_file);

  fclose(bitmap_file);
}

int get_next_free_block(t_bitarray *bitarray) {
  int i = 0;
  while (bitarray_test_bit(bitarray, i))
    i++;

  if (i >= block_count * 8)
    return -1;

  return i;
}

void alloc_n_blocks(t_bitarray *bitarray, uint32_t block_index, uint32_t n) {
  if (n == 0)
    return;
  for (int i = 0; i < n; i++)
    bitarray_set_bit(bitarray, block_index + i);
  set_bitarray_bitmap(bitarray);
}
void dealloc_n_blocks(t_bitarray *bitarray, uint32_t block_index, uint32_t n) {
  if (n == 0)
    return;
  for (int i = 0; i < n; i++)
    bitarray_clean_bit(bitarray, block_index + i);
  set_bitarray_bitmap(bitarray);
}

void fs_create(packet_t *req) {
  char *file_name = packet_read_string(req);
  char *parsed_file_name = parse_file_name(file_name);
  free(file_name);
  t_bitarray *bitmap = get_bitarray_bitmap();

  int free_block = get_next_free_block(bitmap);
  if (free_block == -1) {
    // no hay mas bloques libres
    return;
  }

  alloc_n_blocks(bitmap, free_block, 1);
  destroy_bitarray_bitmap(bitmap);

  file_create(parsed_file_name);
  t_config *meta_data = config_create(parsed_file_name);
  char bloque_inicial[10];
  sprintf(bloque_inicial, "%d", free_block);
  config_set_value(meta_data, "TAMANIO_ARCHIVO", "0");
  config_set_value(meta_data, "BLOQUE_INICIAL", bloque_inicial);
  config_save(meta_data);
  config_destroy(meta_data);

  free(parsed_file_name);
}

void fs_delete(packet_t *req) {
  char *file_name = packet_read_string(req);
  char *parsed_file_name = parse_file_name(file_name);
  free(file_name);

  t_config *meta_data = config_create(parsed_file_name);
  char *bloque_inicial = config_get_string_value(meta_data, "BLOQUE_INICIAL");
  char *file_size = config_get_string_value(meta_data, "TAMANIO_ARCHIVO");
  config_destroy(meta_data);

  uint32_t file_block_count = strtol(file_size, NULL, 10) / block_size;
  uint32_t bloque_inicial_int = strtol(bloque_inicial, NULL, 10);

  t_bitarray *bitmap = get_bitarray_bitmap();
  dealloc_n_blocks(bitmap, bloque_inicial_int, file_block_count);
  destroy_bitarray_bitmap(bitmap);

  remove(parsed_file_name);
  free(parsed_file_name);
}

void fs_read(packet_t *req) {
  char *file_name = packet_read_string(req);
  char *parsed_file_name = parse_file_name(file_name);
  free(file_name);

  // uint32_t size = packet_read_uint32(req);
  // uint32_t offset = packet_read_uint32(req);
  // uint32_t address = packet_read_uint32(req);

  // leer del archivo file_name, a partir del offset, una cantidad size de bytes
  // y enviar a memoria para escribir en la direccion address

  free(parsed_file_name);
}

void fs_write(packet_t *req) {
  char *file_name = packet_read_string(req);
  char *parsed_file_name = parse_file_name(file_name);
  free(file_name);

  // uint32_t size = packet_read_uint32(req);
  // uint32_t offset = packet_read_uint32(req);
  // uint32_t address = packet_read_uint32(req);

  // leer de la dirreccion addres de memoria una cantidad size de bytes
  // y escribir en el archivo con nombre file_name a partir del offset
  free(parsed_file_name);
}

void fs_truncate(packet_t *req) {
  char *file_name = packet_read_string(req);
  char *parsed_file_name = parse_file_name(file_name);
  free(file_name);

  // uint32_t size = packet_read_uint32(req);
  // modificar archivo con nombre file_name para que el tamanio sea size bytes
  free(parsed_file_name);
}

void interfaz_dialfs(packet_t *res, int socket_kernel) {
  instruction_op op;
  packet_read(res, &op, sizeof(instruction_op));
  switch (op) {
  case IO_FS_CREATE:
    fs_create(res);
    break;
  case IO_FS_READ:
    fs_read(res);
    break;
  case IO_FS_WRITE:
    fs_write(res);
    break;
  case IO_FS_DELETE:
    fs_delete(res);
    break;
  case IO_FS_TRUNCATE:
    fs_truncate(res);
    break;
  default:
    break;
  }

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
  ;
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
