#include <commons/bitarray.h>
#include <commons/config.h>
#include <commons/log.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <utils/buffer.h>
#include <utils/connection.h>
#include <utils/exit.h>
#include <utils/file.h>
#include <utils/instruction.h>
#include <utils/packet.h>
#include <utils/status.h>

#define MAX_METADATA_VALUE_LENGTH 10
#define FILE_SIZE_KEY "TAMANIO_ARCHIVO"
#define INITIAL_BLOCK_KEY "BLOQUE_INICIAL"

t_log *logger;
t_config *config;

char *name;
char *io_type;
int tiempo_unidad_trabajo_ms;
int retraso_compactacion;

char *ip_kernel;
char *puerto_kernel;

char *ip_memoria;
char *puerto_memoria;

char *path_base_dialfs;
int block_size;
int block_count;
int socket_kernel;

void clean_up() {
  connection_close(socket_kernel);
  config_destroy(config);
  log_destroy(logger);
}

void sigint_handler() {
  clean_up();
  exit(EXIT_FAILURE);
}

int ceil_div(uint32_t num, int denom) { return (num + denom - 1) / denom; }

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
  uint32_t pid = packet_read_uint32(res);
  uint32_t splits = packet_read_uint32(res);

  buffer_t *buffer_write = buffer_create();
  for (int i = 0; i < splits; i++) {
    uint32_t address = packet_read_uint32(res);
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
    connection_close(socket_memoria);
    for (int j = 0; j < size; j++) {
      uint8_t byte = packet_read_uint8(res_memoria);
      buffer_add_uint8(buffer_write, byte);
    }
    packet_destroy(res_memoria);
  }

  buffer_add_uint8(buffer_write, '\0');
  printf("%s\n", (char *)buffer_write->stream);
  buffer_destroy(buffer_write);
  packet_t *res_kernel = status_pack(OK);
  packet_send(res_kernel, socket_kernel);
  packet_destroy(res_kernel);
}

void interfaz_stdin(packet_t *res, int socket_kernel) {
  uint32_t pid = packet_read_uint32(res);
  uint32_t size = packet_read_uint32(res);
  uint32_t splits = packet_read_uint32(res);

  printf("Ingrese string de %u caracteres a guardar en memoria\n>", size);
  char *input = NULL;
  size_t length = 0;
  length = getline(&input, &length, stdin);
  input[length - 1] = '\0';

  buffer_t *buffer_read = buffer_create();
  buffer_add_string(buffer_read, length, input);

  for (int i = 0; i < splits; i++) {
    uint32_t address = packet_read_uint32(res);
    uint32_t split_size = packet_read_uint32(res);
    int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);
    if (socket_memoria == -1)
      exit_client_connection_error(logger);

    packet_t *req = packet_create(WRITE_DIR);
    packet_add_uint32(req, address);
    packet_add_uint32(req, pid);
    packet_add_uint32(req, split_size);

    for (int j = 0; j < split_size; j++) {
      uint8_t byte = buffer_read_uint8(buffer_read);
      log_info(logger, "Se escribio %c en la direccion %u", (char)byte,
               address + j);
      packet_add_uint8(req, byte);
    }

    packet_send(req, socket_memoria);
    packet_destroy(req);
  }
  buffer_destroy(buffer_read);

  packet_t *res_kernel = status_pack(OK);
  packet_send(res_kernel, socket_kernel);
  packet_destroy(res_kernel);
}

char *parse_file_name(char *file_name) {
  return file_concat_path(path_base_dialfs, file_name);
}

void destroy_bitarray_bitmap(t_bitarray *bitarray) {
  free(bitarray->bitarray);
  bitarray_destroy(bitarray);
}

int get_bitmap_fd(int o_flags) {
  char *bitmap_path = parse_file_name("/bitmap.dat");
  int fd = open(bitmap_path, o_flags);
  free(bitmap_path);
  return fd;
}

int get_blocks_fd(int o_flags) {
  char *blocks_path = parse_file_name("/bloques.dat");
  int fd = open(blocks_path, o_flags);
  free(blocks_path);
  return fd;
}

t_bitarray *get_bitarray_bitmap(int bitmap_fd) {
  char *buffer = 0;
  long length = block_count / 8;

  buffer = malloc((length + 1) * sizeof(char));
  read(bitmap_fd, buffer, length * sizeof(char));
  buffer[length] = '\0';

  return bitarray_create_with_mode(buffer, block_count, MSB_FIRST);
}

void free_bitarray_bitmap(t_bitarray *bitarray, int bitmap_fd) {
  close(bitmap_fd);
  destroy_bitarray_bitmap(bitarray);
}

void set_bitarray_bitmap(t_bitarray *bitarray, int bitmap_fd) {
  write(bitmap_fd, bitarray->bitarray, sizeof(char) * block_count / 8);
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
}

void dealloc_n_blocks(t_bitarray *bitarray, uint32_t block_index, uint32_t n) {
  if (n == 0)
    return;
  for (int i = 0; i < n; i++)
    bitarray_clean_bit(bitarray, block_index + i);
}

buffer_t *read_n_blocks(int initial_block, uint32_t n) {
  buffer_t *buff = buffer_create();
  buff->stream = malloc(n * block_size);

  int fd = get_blocks_fd(O_RDONLY);
  struct flock lock =
      file_lock(fd, F_RDLCK, initial_block * block_size, n * block_size);

  lseek(fd, initial_block * block_size, SEEK_SET);
  read(fd, buff->stream, n * block_size);

  file_unlock(fd, lock);

  close(fd);
  buff->size += n * block_size;
  return buff;
}

void write_n_blocks(int initial_block, uint32_t n, buffer_t *buff) {
  int fd = get_blocks_fd(O_WRONLY);
  struct flock lock =
      file_lock(fd, F_WRLCK, initial_block * block_size, n * block_size);

  lseek(fd, initial_block * block_size, SEEK_SET);
  write(fd, buff->stream, n * block_size);

  file_unlock(fd, lock);

  close(fd);
  buff->offset += n * block_size;
}

int get_metadata(char *file_name, char *key) {
  t_config *metadata = config_create(file_name);
  int data = config_get_int_value(metadata, key);
  config_destroy(metadata);
  return data;
}

void set_metadata(char *file_name, char *key, int value) {
  t_config *metadata = config_create(file_name);
  char data[MAX_METADATA_VALUE_LENGTH];
  sprintf(data, "%d", value);
  config_set_value(metadata, key, data);
  config_save(metadata);
  config_destroy(metadata);
}

void create_metadata(char *file_name, int initial_block) {
  file_create(file_name);
  set_metadata(file_name, INITIAL_BLOCK_KEY, initial_block);
  set_metadata(file_name, FILE_SIZE_KEY, 0);
}

void destroy_metadata(char *file_name) { remove(file_name); }

void fs_create(char *file_name) {
  int bitmap_fd = get_bitmap_fd(O_RDWR);
  struct flock lock = file_lock(bitmap_fd, F_WRLCK, 0, 0);

  t_bitarray *bitmap = get_bitarray_bitmap(bitmap_fd);
  int free_block = get_next_free_block(bitmap);
  if (free_block == -1) {
    // no hay mas bloques libres
    free_bitarray_bitmap(bitmap, bitmap_fd);
    return;
  }
  alloc_n_blocks(bitmap, free_block, 1);
  set_bitarray_bitmap(bitmap, bitmap_fd);
  file_unlock(bitmap_fd, lock);

  free_bitarray_bitmap(bitmap, bitmap_fd);
  create_metadata(file_name, free_block);
}

void fs_delete(char *file_name) {
  int file_size = get_metadata(file_name, FILE_SIZE_KEY);
  int initial_block = get_metadata(file_name, INITIAL_BLOCK_KEY);
  uint32_t file_block_count = file_size / block_size;

  int bitmap_fd = get_bitmap_fd(O_RDWR);
  struct flock lock = file_lock(bitmap_fd, F_WRLCK, 0, 0);

  t_bitarray *bitmap = get_bitarray_bitmap(bitmap_fd);

  if (file_block_count == 0)
    dealloc_n_blocks(bitmap, initial_block, 1);
  else
    dealloc_n_blocks(bitmap, initial_block, file_block_count);
  set_bitarray_bitmap(bitmap, bitmap_fd);

  file_unlock(bitmap_fd, lock);

  free_bitarray_bitmap(bitmap, bitmap_fd);
  destroy_metadata(file_name);
}

void fs_read(char *file_name, uint32_t pid, packet_t *req) {
  uint32_t size = packet_read_uint32(req);
  uint32_t offset = packet_read_uint32(req);
  uint32_t address = packet_read_uint32(req);

  int initial_block = get_metadata(file_name, INITIAL_BLOCK_KEY);

  buffer_t *buff = read_n_blocks(initial_block + offset, size);

  int socket = connection_create_client(ip_memoria, puerto_memoria);
  packet_t *req_memoria = packet_create(WRITE_DIR);
  packet_add_uint32(req_memoria, address);
  packet_add_uint32(req_memoria, pid);
  packet_add_uint32(req_memoria, size);

  for (int i = 0; i < size; i++) {
    uint8_t byte = buffer_read_uint8(buff);
    packet_add_uint8(req_memoria, byte);
  }

  buffer_destroy(buff);
  packet_send(req_memoria, socket);
  packet_destroy(req_memoria);
  connection_close(socket);
}

void fs_write(char *file_name, uint32_t pid, packet_t *req) {
  uint32_t size = packet_read_uint32(req);
  uint32_t offset = packet_read_uint32(req);
  uint32_t address = packet_read_uint32(req);

  int socket = connection_create_client(ip_memoria, puerto_memoria);
  packet_t *req_memoria = packet_create(READ_DIR);
  packet_add_uint32(req_memoria, address);
  packet_add_uint32(req_memoria, pid);
  packet_add_uint32(req_memoria, size);
  packet_send(req_memoria, socket);
  packet_destroy(req_memoria);

  packet_t *res_memoria = packet_recieve(socket);

  buffer_t *buff = buffer_create();
  for (int i = 0; i < size; i++) {
    uint8_t byte = packet_read_uint8(res_memoria);
    buffer_add_uint8(buff, byte);
  }
  packet_destroy(res_memoria);

  int initial_block = get_metadata(file_name, INITIAL_BLOCK_KEY);
  write_n_blocks(initial_block + offset, size, buff);

  buffer_destroy(buff);
  connection_close(socket);
}

void compact(t_bitarray *bitmap) {
  usleep(1000 * retraso_compactacion);
  int compacts = 0;
  do {
    compacts = 0;
    int i = 1;
    int j = 0;
    while (j < block_count) {
      bool bit_i = bitarray_test_bit(bitmap, i);
      bool bit_j = bitarray_test_bit(bitmap, j);
      if (bit_i && !bit_j) {
        compacts++;
        buffer_t *buff = read_n_blocks(i, 1);
        dealloc_n_blocks(bitmap, i, 1);
        alloc_n_blocks(bitmap, j, 1);
        write_n_blocks(j, 1, buff);
        buffer_destroy(buff);
      }
      i++;
      j++;
    }
  } while (compacts != 0);
}

int can_file_extend(t_bitarray *bitmap, char *file_name, int blocks_to_extend) {
  int file_size = get_metadata(file_name, FILE_SIZE_KEY);
  int initial_block = get_metadata(file_name, INITIAL_BLOCK_KEY);
  int file_blocks = file_size / block_size;

  int i = 0;
  int cont_i = 0;
  int free_blocks = 0;
  while (i < block_count) {
    bool bit = bitarray_test_bit(bitmap, i);
    if (!bit)
      free_blocks++;

    if (i >= initial_block + file_blocks) {
      if (!bit)
        cont_i++;

      if (cont_i == blocks_to_extend)
        return i - blocks_to_extend + 1;
    }
    i++;
  }
  if (free_blocks >= blocks_to_extend)
    return -1; // se puede compactar
  return -2;
}

void fs_truncate(char *file_name, packet_t *req) {
  uint32_t size = packet_read_uint32(req);
  if (size == 0)
    return fs_delete(file_name);
  uint32_t file_size = get_metadata(file_name, FILE_SIZE_KEY);
  uint32_t file_blocks = file_size / block_size;
  uint32_t initial_block = get_metadata(file_name, INITIAL_BLOCK_KEY);
  if (file_size == size)
    return;
  int reduce = file_size > size;

  int fd = get_bitmap_fd(O_RDWR);
  struct flock lock = file_lock(fd, F_WRLCK, 0, 0);
  t_bitarray *bitmap = get_bitarray_bitmap(fd);

  if (reduce) {
    uint32_t block_difference = (file_size - size) / block_size;
    dealloc_n_blocks(bitmap, initial_block + file_blocks - block_difference,
                     block_difference);
    set_bitarray_bitmap(bitmap, fd);
  } else {
    uint32_t block_difference = ceil_div(size - file_size, block_size);
    int free_block = can_file_extend(bitmap, file_name, block_difference);
    if (free_block == -2) { // Out of memory
      bitarray_destroy(bitmap);
    } else if (free_block == -1) {
      buffer_t *buff = read_n_blocks(initial_block, file_size);
      dealloc_n_blocks(bitmap, initial_block, file_size);
      compact(bitmap);
      int next_free_block = get_next_free_block(bitmap);
      alloc_n_blocks(bitmap, next_free_block, file_size + block_difference);
      set_bitarray_bitmap(bitmap, fd);
      write_n_blocks(free_block, file_size + block_difference, buff);
      buffer_destroy(buff);
    } else {
      alloc_n_blocks(bitmap, free_block, size);
      set_bitarray_bitmap(bitmap, fd);
    }
  }

  file_unlock(fd, lock);
  free_bitarray_bitmap(bitmap, fd);
}

void interfaz_dialfs(packet_t *res, int socket_kernel) {
  usleep(tiempo_unidad_trabajo_ms * 1000);
  instruction_op op;
  packet_read(res, &op, sizeof(instruction_op));

  char *file_name = packet_read_string(res);
  uint32_t pid = packet_read_uint32(res);
  char *parsed_file_name = parse_file_name(file_name);
  free(file_name);

  switch (op) {
  case IO_FS_CREATE:
    fs_create(parsed_file_name);
    break;
  case IO_FS_READ:
    fs_read(parsed_file_name, pid, res);
    break;
  case IO_FS_WRITE:
    fs_write(parsed_file_name, pid, res);
    break;
  case IO_FS_DELETE:
    fs_delete(parsed_file_name);
    break;
  case IO_FS_TRUNCATE:
    fs_truncate(parsed_file_name, res);
    break;
  default:
    break;
  }
  free(parsed_file_name);

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
  return strcmp(io_type, "GENERICA") == 0 || strcmp(io_type, "STDIN") == 0 ||
         strcmp(io_type, "STDOUT") == 0 || strcmp(io_type, "DIALFS") == 0;
}

void print_bitarray(t_bitarray *bitarray) {
  int i = 0;
  while (i < block_count) {
    bool bit = bitarray_test_bit(bitarray, i);
    if (bit)
      printf("1");
    else
      printf("0");
    if ((i + 1) % 16 == 0)
      printf("\n");
    i++;
  }
}

void print_blocks() {
  int i = 0;
  while (i < block_count) {
    buffer_t *buff = read_n_blocks(i, 1);
    uint8_t byte = buffer_read_uint8(buff);
    uint8_t byte2 = buffer_read_uint8(buff);
    printf("%c", byte);
    printf("%c", byte2);
    if ((i + 1) % 16 == 0)
      printf("\n");
    i++;
    buffer_destroy(buff);
  }
}

int main(int argc, char *argv[]) {
  struct sigaction sa;
  sa.sa_handler = &sigint_handler;
  sa.sa_flags = SA_RESTART;
  sigaction(SIGINT, &sa, NULL);

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
  retraso_compactacion = config_get_int_value(config, "RETRASO_COMPACTACION");

  path_base_dialfs = config_get_string_value(config, "PATH_BASE_DIALFS");
  block_size = config_get_int_value(config, "BLOCK_SIZE");
  block_count = config_get_int_value(config, "BLOCK_COUNT");

  socket_kernel = connection_create_client(ip_kernel, puerto_kernel);
  request_register_io(socket_kernel);
  while (1) {
    packet_t *res = packet_recieve(socket_kernel);
    if (res->type == STATUS) {
      status_code status = status_unpack(res);
      if (status == ERROR) {
        log_error(logger, "La conexion fue rechazada");
        break;
      }
    }
    if (strcmp(io_type, "GENERICA") == 0) {
      interfaz_generica(res, socket_kernel);
    } else if (strcmp(io_type, "STDIN") == 0) {
      interfaz_stdin(res, socket_kernel);
    } else if (strcmp(io_type, "STDOUT") == 0) {
      interfaz_stdout(res, socket_kernel);
    } else if (strcmp(io_type, "DIALFS") == 0)
      interfaz_dialfs(res, socket_kernel);
    packet_destroy(res);
  }
  clean_up();
  return EXIT_SUCCESS;
}
