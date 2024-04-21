#include <commons/collections/dictionary.h>
#include <commons/collections/queue.h>
#include <commons/config.h>
#include <commons/log.h>
#include <ctype.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <utils/connection.h>
#include <utils/exit.h>
#include <utils/instruction.h>
#include <utils/packet.h>
#include <utils/process.h>
#include <utils/status.h>

#define FILE_NAME_MAX_LENGTH 60

t_log *logger;
t_config *config;

char *puerto_escucha;

char *ip_memoria;
char *puerto_memoria;

char *ip_cpu;
char *puerto_cpu_dispatch;
char *puerto_cpu_interrupt;

char *algoritmo_planificacion;
int quantum;
char **recursos;
char **instancias_recursos;
int grado_multiprogramacion;

int next_pid = 0;
t_queue *new_queue;
t_queue *ready_queue;
process_t *exec = NULL;
t_list *finished;
// seran multiples colas
t_queue *blocked;

typedef struct {
  int socket;
  char *type;
} io;
t_dictionary *io_dict;

void free_io(void *e) {
  io *interface = (io *)e;
  free(interface->type);
  free(interface);
}

void print_process_queue(t_queue *queue, char *name) {

  if (queue_is_empty(queue)) {
    printf("La cola %s esta vacia\n", name);
    return;
  }

  process_t *head = queue_pop(queue);
  uint32_t head_pid = head->pid;
  process_print(*head);
  queue_push(queue, head);

  process_t *aux_process = queue_peek(queue);
  uint32_t aux_pid = aux_process->pid;

  while (aux_pid != head_pid) {
    aux_process = queue_pop(queue);
    process_print(*aux_process);
    queue_push(queue, aux_process);
    aux_process = queue_peek(queue);
    aux_pid = aux_process->pid;
  }
}

status_code request_init_process(char *path) {

  int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);
  if (socket_memoria == -1)
    exit_client_connection_error(logger);

  packet_t *packet = packet_create(INIT_PROCESS);
  packet_add_string(packet, path);
  packet_send(packet, socket_memoria);
  packet_destroy(packet);

  packet_t *res = packet_recieve(socket_memoria);
  uint8_t status_code = status_unpack(res);
  packet_destroy(res);
  connection_close(socket_memoria);
  return status_code;
}

void response_register_io(packet_t *request, int io_socket) {
  char *nombre = packet_read_string(request);
  char *tipo_interfaz = packet_read_string(request);

  log_info(logger, "Se conecto una interfaz de tipo %s y nombre %s",
           tipo_interfaz, nombre);

  io *interfaz = malloc(sizeof(io));
  interfaz->type = strdup(tipo_interfaz);
  interfaz->socket = io_socket;

  dictionary_put(io_dict, nombre, interfaz);
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
  packet_destroy(request);
  free(args);
  return EXIT_SUCCESS;
}

void exec_script(void) {}

void init_process(void) {
  printf("Ingresar path al archivo de instrucciones\n");
  char path[FILE_NAME_MAX_LENGTH];
  int c;
  while ((c = getchar()) != '\n' && c != EOF) {
  }

  fgets(path, FILE_NAME_MAX_LENGTH - 1, stdin);
  if (strlen(path) < FILE_NAME_MAX_LENGTH + 1) {
    path[strlen(path) - 1] = '\0';
  }
  status_code res_status = request_init_process(path);
  if (res_status == OK) {
    uint32_t pid = next_pid;
    next_pid++;
    process_t *new_process = process_create(pid, strdup(path), quantum);
    queue_push(new_queue, new_process);
    log_info(logger, "Se crea el proceso %d en NEW", pid);
  } else if (res_status == NOT_FOUND) {
    log_error(logger, "El archivo %s no existe", path);
  }
};

void end_process(void) {}
void stop_scheduler(void) {}
void start_scheduler(void) {}
void change_multiprogramming(void) {}

void list_processes(void) {
  print_process_queue(new_queue, "NEW");
  print_process_queue(ready_queue, "READY");
  // imprimir el resto de procesos
};

process_t *request_cpu_interrupt(int socket_cpu_dispatch) {
  int socket_cpu_interrupt =
      connection_create_client(ip_cpu, puerto_cpu_interrupt);
  if (socket_cpu_interrupt == -1)
    exit_client_connection_error(logger);

  packet_t *req = packet_create(INTERRUPT);
  packet_send(req, socket_cpu_interrupt);
  packet_destroy(req);
  connection_close(socket_cpu_interrupt);

  packet_t *res = packet_recieve(socket_cpu_dispatch);
  process_t updated_process = process_unpack(res);
  process_t *p = process_dup(updated_process);
  packet_destroy(res);
  return p;
}

process_t *wait_process_exec(int socket_cpu_dispatch, int *finish_process) {
  packet_t *res = packet_recieve(socket_cpu_dispatch);

  switch (res->type) {
  case BLOCKING_OP: {
    uint32_t instruction = packet_read_uint32(res);
    char *nombre = packet_read_string(res);

    if (dictionary_has_key(io_dict, nombre)) {
      io *interfaz = dictionary_get(io_dict, nombre);
      packet_t *io_res = packet_create(REGISTER_IO);
      switch (instruction) {
      case IO_GEN_SLEEP: {
        long tiempo_espera;
        packet_read(res, &tiempo_espera, sizeof(long));
        packet_destroy(res);
        packet_add(io_res, &tiempo_espera, sizeof(long));
        break;
      }
      case IO_STDIN_READ: {
        long tiempo_espera;
        packet_read(res, &tiempo_espera, sizeof(long));
        packet_destroy(res);
        packet_add(io_res, &tiempo_espera, sizeof(long));
        break;
      }
      case IO_STDOUT_WRITE: {
        long tiempo_espera;
        packet_read(res, &tiempo_espera, sizeof(long));
        packet_destroy(res);
        packet_add(io_res, &tiempo_espera, sizeof(long));
        break;
      }
      default:
        break;
      }
      packet_send(io_res, interfaz->socket);
      packet_destroy(io_res);
    } else {
      packet_destroy(res);
      *finish_process = 1;
    }
    return request_cpu_interrupt(socket_cpu_dispatch);
  }
  case NON_BLOCKING_OP:
    packet_destroy(res);
    return NULL;
  case PROCESS: {
    process_t updated_process = process_unpack(res);
    status_code status = OK;
    packet_read(res, &status, sizeof(status_code));
    packet_destroy(res);
    if (status == END_OF_FILE)
      *finish_process = 1;
    process_t *p = process_dup(updated_process);

    return p;
  }
  default:
    return NULL;
  }
  return NULL;
}

void planificacion_fifo() {
  int socket_cpu_dispatch =
      connection_create_client(ip_cpu, puerto_cpu_dispatch);
  if (socket_cpu_dispatch == -1)
    exit_client_connection_error(logger);

  process_t process_to_exec = {1, "/process1", 2, 0};
  // semaforos... para iniciar y detener planificacion
  // if (exec == NULL && !queue_is_empty(ready_queue)) {
  // process_t *process_to_exec = queue_pop(ready_queue);
  // exec = process_to_exec;
  packet_t *request = process_pack(process_to_exec);
  packet_send(request, socket_cpu_dispatch);
  packet_destroy(request);
  process_t *updated_process = NULL;
  int finish_process = 0;
  while (updated_process == NULL)
    updated_process = wait_process_exec(socket_cpu_dispatch, &finish_process);

  if (finish_process == 1) {
  }
  connection_close(socket_cpu_dispatch);
}

void *consola_interactiva(void *args) {
  char input = '0';
  do {
    if (isdigit(input)) {
      printf("+------------------------------------------+\n");
      printf("| %-40s |\n", "1: Ejecutar script");
      printf("| %-40s |\n", "2: Iniciar proceso");
      printf("| %-40s |\n", "3: Finalizar proceso");
      printf("| %-40s |\n", "4: Detener planificacion");
      printf("| %-40s |\n", "5: Iniciar planificacion");
      printf("| %-40s |\n", "6: Cambiar grado de multiprogramacion");
      printf("| %-40s |\n", "7: Listar estados de procesos");
      printf("+------------------------------------------+\n");
    }
    input = getchar();
    switch (input) {
    case '1':
      exec_script();
      break;
    case '2':
      init_process();
      break;
    case '3':
      end_process();
      break;
    case '4':
      stop_scheduler();
      break;
    case '5': {
      planificacion_fifo();
      // start_scheduler();
      break;
    }
    case '6':
      change_multiprogramming();
      break;
    case '7':
      list_processes();
      break;
    default:
      printf("Invalid input\n");
      break;
    }

  } while (1);
  return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
  logger = log_create("kernel.log", "KERNEL", 1, LOG_LEVEL_DEBUG);
  if (argc < 2)
    exit_not_enough_arguments_error(logger);

  config = config_create(argv[1]);
  if (config == NULL)
    exit_enoent_erorr(logger);

  puerto_escucha = config_get_string_value(config, "PUERTO_ESCUCHA");

  ip_memoria = config_get_string_value(config, "IP_MEMORIA");
  puerto_memoria = config_get_string_value(config, "PUERTO_MEMORIA");

  ip_cpu = config_get_string_value(config, "IP_CPU");
  puerto_cpu_dispatch = config_get_string_value(config, "PUERTO_CPU_DISPATCH");
  puerto_cpu_interrupt =
      config_get_string_value(config, "PUERTO_CPU_INTERRUPT");

  algoritmo_planificacion =
      config_get_string_value(config, "ALGORITMO_PLANIFICACION");
  quantum = config_get_int_value(config, "QUANTUM");
  instancias_recursos = config_get_array_value(config, "INSTANCIAS_RECURSOS");
  recursos = config_get_array_value(config, "RECURSOS");
  grado_multiprogramacion =
      config_get_int_value(config, "GRADO_MULTIPROGRAMACION");

  new_queue = queue_create();
  ready_queue = queue_create();
  exec = NULL;

  io_dict = dictionary_create();

  int server_socket = connection_create_server(puerto_escucha);
  if (server_socket == -1)
    exit_server_connection_error(logger);
  log_info(logger, "Servidor levantado en el puerto %s", puerto_escucha);

  pthread_t console_thread;
  pthread_create(&console_thread, NULL, &consola_interactiva, NULL);
  while (1) {
    int client_socket = connection_accept_client(server_socket);
    if (client_socket == -1)
      continue;
    pthread_t thread;
    int *arg = malloc(sizeof(int));
    *arg = client_socket;
    pthread_create(&thread, NULL, &atender_cliente, arg);
    pthread_detach(thread);
  }

  dictionary_destroy_and_destroy_elements(io_dict, &free_io);
  queue_destroy_and_destroy_elements(new_queue, (void *)&process_destroy);
  queue_destroy_and_destroy_elements(ready_queue, (void *)&process_destroy);
  queue_destroy(ready_queue);
  pthread_join(console_thread, NULL);
  connection_close(server_socket);
  log_destroy(logger);
  config_destroy(config);
  return EXIT_SUCCESS;
}
