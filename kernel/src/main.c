#include <commons/collections/dictionary.h>
#include <commons/collections/list.h>
#include <commons/collections/queue.h>
#include <commons/config.h>
#include <commons/log.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <utils/command.h>
#include <utils/connection.h>
#include <utils/exit.h>
#include <utils/file.h>
#include <utils/instruction.h>
#include <utils/packet.h>
#include <utils/process.h>
#include <utils/status.h>

#define FILE_NAME_MAX_LENGTH 60
#define FILE_LINE_MAX_LENGTH 80

typedef enum {
  BLOCK,
  FINISH,
} interrupt;

typedef struct {
  int socket;
  char *type;
  int queue_index;
} io;
t_dictionary *io_dict;

void exec_script(char *path);

t_log *logger;
t_config *config;

char *puerto_escucha;

char *ip_memoria;
char *puerto_memoria;

char *ip_cpu;
char *puerto_cpu_dispatch;
char *puerto_cpu_interrupt;

char *algoritmo_planificacion;
int initial_quantum;
char **recursos;
char **instancias_recursos;
int grado_multiprogramacion;
char *path_instrucciones;

int next_pid = 0;
int is_scheduler_running = 0;

t_queue *new_queue;
t_queue *ready_queue;
process_t *exec = NULL;
t_list *blocked;
t_list *finished;

pthread_mutex_t mutex_io_dict;
pthread_mutex_t mutex_algoritmo_planificacion;
pthread_mutex_t mutex_multiprogramacion;
pthread_mutex_t mutex_scheduler;

pthread_mutex_t mutex_new;
pthread_mutex_t mutex_ready;
pthread_mutex_t mutex_exec;
pthread_mutex_t mutex_blocked;
pthread_mutex_t mutex_finished;

sem_t sem_ready_empty;
sem_t sem_ready_full;
sem_t sem_new_full;
sem_t sem_exec_full;
sem_t sem_exec_empty;

sem_t sem_scheduler;

void free_io(void *e) {
  io *interface = (io *)e;
  free(interface->type);
  free(interface);
}

// uint8_t is_multiprogramming_full() {
//   int procesos_en_memoria = queue_size(ready_queue);
//   if (exec != NULL)
//     procesos_en_memoria++;
//   // los bloqueados cuentan ??
//   pthread_mutex_lock(&mutex_multiprogramacion);
//   uint8_t is_full = procesos_en_memoria >= grado_multiprogramacion;
//   pthread_mutex_unlock(&mutex_multiprogramacion);
//   return is_full;
// }
//
// void queue_push_ready_or_new(process_t *process) {
//
//   if (is_multiprogramming_full()) {
//     pthread_mutex_lock(&mutex_new);
//     queue_push(new_queue, process);
//     pthread_mutex_unlock(&mutex_new);
//
//   } else {
//     pthread_mutex_lock(&mutex_ready);
//     queue_push(ready_queue, process);
//     pthread_mutex_unlock(&mutex_ready);
//
//     log_info(logger,
//              "Se agrega el proceso %d a READY porque el grado de "
//              "multiprogramacion lo permite",
//              process->pid);
//   }
// }

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
  t_queue *io_queue = queue_create();

  pthread_mutex_lock(&mutex_blocked);
  int index = list_add(blocked, io_queue);
  pthread_mutex_unlock(&mutex_blocked);

  interfaz->queue_index = index;
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

void free_process(uint32_t pid) {
  int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);
  packet_t *free_req = packet_create(FREE_PROCESS);
  packet_add_uint32(free_req, pid);
  packet_send(free_req, socket_memoria);
  packet_destroy(free_req);
}

void init_process(char *path) {
  status_code res_status = request_init_process(path);
  if (res_status == OK) {
    process_t *new_process =
        process_create(next_pid, strdup(path), initial_quantum);

    pthread_mutex_lock(&mutex_new);
    queue_push(new_queue, new_process);
    pthread_mutex_unlock(&mutex_new);
    sem_post(&sem_new_full);

    log_info(logger, "Se crea el proceso %d en NEW", new_process->pid);
    next_pid++;
  } else if (res_status == NOT_FOUND) {
    log_error(logger, "El archivo %s no existe", path);
  }
};

process_t *request_cpu_interrupt(int interrupt, int socket_cpu_dispatch) {
  int socket_cpu_interrupt =
      connection_create_client(ip_cpu, puerto_cpu_interrupt);
  if (socket_cpu_interrupt == -1)
    exit_client_connection_error(logger);

  packet_t *req = packet_create(interrupt == 0 ? STATUS : INTERRUPT);
  packet_send(req, socket_cpu_interrupt);
  packet_destroy(req);
  connection_close(socket_cpu_interrupt);
  if (interrupt == 0)
    return NULL;

  packet_t *res = packet_recieve(socket_cpu_dispatch);
  process_t updated_process = process_unpack(res);
  process_t *p = process_dup(updated_process);
  packet_destroy(res);
  return p;
}

void *unblock_process(void *args) {
  char *nombre = (char *)args;
  io *interfaz = dictionary_get(io_dict, nombre);
  packet_t *packet = packet_recieve(interfaz->socket);
  status_code status = status_unpack(packet);
  if (status == OK) {
    pthread_mutex_lock(&mutex_blocked);
    t_queue *blocked_queue = list_get(blocked, interfaz->queue_index);
    process_t *blocked_process = queue_pop(blocked_queue);
    pthread_mutex_unlock(&mutex_blocked);

    sem_wait(&sem_ready_empty);
    pthread_mutex_lock(&mutex_ready);

    queue_push(ready_queue, blocked_process);

    pthread_mutex_unlock(&mutex_ready);
    sem_post(&sem_ready_full);
  }
  free(args);
  return EXIT_SUCCESS;
}

void response_io_gen_sleep(packet_t *res, char *nombre) {
  io *interfaz = dictionary_get(io_dict, nombre);
  packet_t *io_res = packet_create(REGISTER_IO);

  uint32_t tiempo_espera = packet_read_uint32(res);
  packet_destroy(res);
  packet_add_uint32(io_res, tiempo_espera);

  packet_send(io_res, interfaz->socket);
  packet_destroy(io_res);

  pthread_t wait_for_io_thread;
  char *arg = strdup(nombre);
  pthread_create(&wait_for_io_thread, NULL, &unblock_process, arg);
  pthread_detach(wait_for_io_thread);
}

void response_io_stdin(packet_t *res, char *nombre) {
  io *interfaz = dictionary_get(io_dict, nombre);
  packet_t *io_res = packet_create(REGISTER_IO);

  uint32_t address = packet_read_uint32(res);
  uint32_t pid = packet_read_uint32(res);
  uint32_t size = packet_read_uint32(res);
  packet_destroy(res);
  packet_add_uint32(io_res, address);
  packet_add_uint32(io_res, pid);
  packet_add_uint32(io_res, size);

  packet_send(io_res, interfaz->socket);
  packet_destroy(io_res);

  pthread_t wait_for_io_thread;
  char *arg = strdup(nombre);
  pthread_create(&wait_for_io_thread, NULL, &unblock_process, arg);
  pthread_detach(wait_for_io_thread);
}

void response_io_stdout(packet_t *res, char *nombre) {
  io *interfaz = dictionary_get(io_dict, nombre);
  packet_t *io_res = packet_create(REGISTER_IO);

  uint32_t address = packet_read_uint32(res);
  uint32_t pid = packet_read_uint32(res);
  uint32_t size = packet_read_uint32(res);
  packet_destroy(res);
  packet_add_uint32(io_res, address);
  packet_add_uint32(io_res, pid);
  packet_add_uint32(io_res, size);

  packet_send(io_res, interfaz->socket);
  packet_destroy(io_res);

  pthread_t wait_for_io_thread;
  char *arg = strdup(nombre);
  pthread_create(&wait_for_io_thread, NULL, &unblock_process, arg);
  pthread_detach(wait_for_io_thread);
}

process_t *wait_process_exec(int socket_cpu_dispatch, interrupt *exit,
                             char **name) {
  packet_t *res = packet_recieve(socket_cpu_dispatch);
  switch (res->type) {
  case INSTRUCTION: {
    instruction_op op = packet_read_uint32(res);
    if (!instruction_is_blocking(op))
      return request_cpu_interrupt(0, socket_cpu_dispatch);

    char *nombre = packet_read_string(res);
    *name = strdup(nombre);
    if (dictionary_has_key(io_dict, nombre)) {
      switch (op) {
      case IO_GEN_SLEEP:
        response_io_gen_sleep(res, nombre);
        break;
      case IO_STDIN_READ:
        response_io_stdin(res, nombre);
        break;
      case IO_STDOUT_WRITE:
        response_io_stdout(res, nombre);
        break;
      default:
        break;
      }
      *exit = BLOCK;
      return request_cpu_interrupt(1, socket_cpu_dispatch);
    } else {
      packet_destroy(res);
      *exit = FINISH;
      return request_cpu_interrupt(1, socket_cpu_dispatch);
    }
  }
  case PROCESS: {
    process_t updated_process = process_unpack(res);
    packet_destroy(res);
    *exit = FINISH;
    process_t *p = process_dup(updated_process);
    return p;
  }
  default:
    return NULL;
  }
  return NULL;
}

void send_new_to_ready() {

  pthread_mutex_lock(&mutex_new);
  process_t *p = queue_pop(new_queue);
  pthread_mutex_unlock(&mutex_new);

  pthread_mutex_lock(&mutex_ready);
  queue_push(ready_queue, p);
  pthread_mutex_unlock(&mutex_ready);
}

void planificacion_fifo() {

  int socket_cpu_dispatch =
      connection_create_client(ip_cpu, puerto_cpu_dispatch);
  if (socket_cpu_dispatch == -1)
    exit_client_connection_error(logger);

  pthread_mutex_lock(&mutex_exec);
  pthread_mutex_lock(&mutex_ready);
  exec = queue_pop(ready_queue);
  pthread_mutex_unlock(&mutex_ready);
  pthread_mutex_unlock(&mutex_exec);
  sem_post(&sem_exec_full);

  packet_t *request = process_pack(*exec);
  packet_send(request, socket_cpu_dispatch);
  packet_destroy(request);

  process_t *updated_process = NULL;
  interrupt exit;
  char *name = NULL;
  while (updated_process == NULL)
    updated_process = wait_process_exec(socket_cpu_dispatch, &exit, &name);

  sem_wait(&sem_exec_full);
  pthread_mutex_lock(&mutex_exec);
  exec = NULL;
  pthread_mutex_unlock(&mutex_exec);
  sem_post(&sem_exec_empty);

  sem_wait(&sem_scheduler);
  sem_post(&sem_scheduler);

  if (exit == FINISH) {
    free_process(updated_process->pid);
    log_info(logger, "Finaliza el proceso %u", updated_process->pid);
    fflush(stdout);
    pthread_mutex_lock(&mutex_finished);
    list_add(finished, updated_process);
    pthread_mutex_unlock(&mutex_finished);
    sem_post(&sem_ready_empty);
  } else if (exit == BLOCK) {
    io *interfaz = dictionary_get(io_dict, name);
    pthread_mutex_lock(&mutex_blocked);
    t_queue *blocked_queue = list_get(blocked, interfaz->queue_index);
    queue_push(blocked_queue, updated_process);
    pthread_mutex_unlock(&mutex_blocked);
  }
  free(name);

  connection_close(socket_cpu_dispatch);
}

void end_process(void) {}

void *scheduler_helper() {
  while (1) {
    sem_wait(&sem_scheduler);
    sem_post(&sem_scheduler);
    pthread_mutex_lock(&mutex_scheduler);
    int run = is_scheduler_running;
    pthread_mutex_unlock(&mutex_scheduler);
    while (run) {
      sem_wait(&sem_new_full);
      sem_wait(&sem_ready_empty);

      pthread_mutex_lock(&mutex_scheduler);
      run = is_scheduler_running;
      pthread_mutex_unlock(&mutex_scheduler);

      if (!run) {
        sem_post(&sem_new_full);
        sem_post(&sem_ready_empty);
        break;
      }

      log_info(logger, "Running scheduler helper....");

      pthread_mutex_lock(&mutex_multiprogramacion);
      send_new_to_ready();
      pthread_mutex_unlock(&mutex_multiprogramacion);

      sem_post(&sem_ready_full);

      pthread_mutex_lock(&mutex_scheduler);
      run = is_scheduler_running;
      pthread_mutex_unlock(&mutex_scheduler);
    }
  }
  return EXIT_SUCCESS;
}

void *scheduler() {
  pthread_t helper;
  pthread_create(&helper, NULL, &scheduler_helper, NULL);
  while (1) {
    sem_wait(&sem_scheduler);
    sem_post(&sem_scheduler);

    pthread_mutex_lock(&mutex_scheduler);
    int run = is_scheduler_running;
    pthread_mutex_unlock(&mutex_scheduler);
    while (run) {
      sem_wait(&sem_ready_full);
      sem_wait(&sem_exec_empty);

      pthread_mutex_lock(&mutex_scheduler);
      run = is_scheduler_running;
      pthread_mutex_unlock(&mutex_scheduler);

      if (!run) {
        sem_post(&sem_ready_full);
        sem_post(&sem_exec_empty);
        break;
      }

      log_info(logger, "Running scheduler....");

      if (strcmp(algoritmo_planificacion, "fifo") == 0)
        planificacion_fifo();
      else if (strcmp(algoritmo_planificacion, "rr") == 0)
        planificacion_fifo();
      else if (strcmp(algoritmo_planificacion, "wr") == 0)
        planificacion_fifo();

      pthread_mutex_lock(&mutex_scheduler);
      run = is_scheduler_running;
      pthread_mutex_unlock(&mutex_scheduler);
    }
  }
  pthread_join(helper, NULL);
}

void stop_scheduler(void) {
  if (is_scheduler_running == 0) {
    log_error(logger, "El Scheduler ya fue detenido");
  } else {
    is_scheduler_running = 0;
    sem_wait(&sem_scheduler);
  }
}

void start_scheduler(void) {
  if (is_scheduler_running == 1) {
    log_error(logger, "El Scheduler ya fue iniciado");
  } else {
    is_scheduler_running = 1;
    sem_post(&sem_scheduler);
  }
}

void change_multiprogramming(uint32_t new_value) {
  pthread_mutex_lock(&mutex_multiprogramacion);
  if (grado_multiprogramacion == new_value) {
    pthread_mutex_unlock(&mutex_multiprogramacion);
    return;
  }
  log_info(logger, "Cambiando multiprogramacion a %u", new_value);
  int reduce = grado_multiprogramacion > new_value;
  if (reduce) {
    int difference = grado_multiprogramacion - new_value;
    for (int i = 0; i < difference; i++)
      sem_wait(&sem_ready_empty);
  } else {
    int difference = new_value - grado_multiprogramacion;
    for (int i = 0; i < difference; i++)
      sem_post(&sem_ready_empty);
  }
  grado_multiprogramacion = new_value;
  log_info(logger, "Multi programacion cambiada a %u", new_value);
  pthread_mutex_unlock(&mutex_multiprogramacion);
}

void finish_process(uint32_t pid) {
  // sacarlo de la cola o estado donde se encuentre

  // liberar su memoria
  free_process(pid);
}

void list_processes(void) {
  pthread_mutex_lock(&mutex_new);
  print_process_queue(new_queue, "NEW");
  pthread_mutex_unlock(&mutex_new);

  pthread_mutex_lock(&mutex_ready);
  print_process_queue(ready_queue, "READY");
  pthread_mutex_unlock(&mutex_ready);
  // imprimir el resto de procesos
};

// FOR DEBUGGING
void read_addr(uint32_t addr) {
  int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);
  packet_t *req = packet_create(READ_DIR);

  packet_add_uint32(req, addr);
  packet_add_uint32(req, 0);
  packet_add_uint32(req, 1);
  packet_send(req, socket_memoria);
  packet_destroy(req);

  packet_t *res = packet_recieve(socket_memoria);
  uint8_t memory_content = packet_read_uint8(res);

  log_debug(logger, "ADDRESS: %u VALUE: %u", addr, memory_content);
}

void exec_command(command_op op, param p) {
  switch (op) {
  case EXEC_SCRIPT:
    exec_script(p.value);
    break;
  case CREATE_PROCESS:
    init_process(p.value);
    break;
  case START_SCHEDULER:
    start_scheduler();
    break;
  case STOP_SCHEDULER:
    stop_scheduler();
    break;
  case PRINT_PROCESSES:
    list_processes();
    break;
  case CHANGE_MULTIPROGRAMMING:
    change_multiprogramming(*(uint32_t *)p.value);
    break;
  case FINISH_PROCESS:
    finish_process(*(uint32_t *)p.value);
    break;
    // FOR DEBUGGING
  case READ_ADDR:
    read_addr(*(uint32_t *)p.value);
    break;
  default:
    break;
  }
}

command_op decode_command(char *command, param *p) {
  char *token = strtok(command, " ");
  if (token == NULL)
    return UNKNOWN_COMMAND;

  command_op op = command_op_from_string(token);
  token = strtok(NULL, " ");
  if (token != NULL) {
    uint32_t *number = malloc(sizeof(uint32_t));
    uint32_t n = strtol(token, NULL, 10);
    memcpy(number, &n, sizeof(uint32_t));

    if (*number != 0 && errno != EINVAL) {
      p->type = NUMBER;
      p->value = number;
    } else {
      free(number);
      p->type = STRING;
      p->value = token;
    }
  }
  return op;
}

void exec_script(char *path) {
  char *full_path = file_concat_path(path_instrucciones, path);

  FILE *script_file = fopen(full_path, "r");
  if (script_file == NULL)
    exit_enoent_error(logger, full_path);

  while (!feof(script_file)) {
    char *command = file_read_next_line(script_file, FILE_LINE_MAX_LENGTH);
    param param;
    command_op op = decode_command(command, &param);
    exec_command(op, param);
    free(command);
  }

  fclose(script_file);
}

void *exec_command_thread(void *args) {
  char *command = (char *)args;
  param p;
  command_op op = decode_command(command, &p);
  exec_command(op, p);

  free(command);
  return EXIT_SUCCESS;
}

void *consola_interactiva(void *args) {
  while (1) {
    printf("Input command:\n> ");
    char *input = NULL;
    size_t length = 0;
    length = getline(&input, &length, stdin);
    input[length - 1] = '\0';

    char *command = malloc(strlen(input) + 1);
    strcpy(command, input);

    param p;
    command_op op = decode_command(input, &p);
    if (op == UNKNOWN_COMMAND) {
      log_error(logger, "%s is not a command", input);
      continue;
    }

    free(input);
    pthread_t exec_thread;
    pthread_create(&exec_thread, NULL, &exec_command_thread, command);
    pthread_detach(exec_thread);
  }
  return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
  logger = log_create("kernel.log", "KERNEL", 1, LOG_LEVEL_DEBUG);
  if (argc < 2)
    exit_not_enough_arguments_error(logger);

  config = config_create(argv[1]);
  if (config == NULL)
    exit_enoent_error(logger, argv[1]);

  puerto_escucha = config_get_string_value(config, "PUERTO_ESCUCHA");

  ip_memoria = config_get_string_value(config, "IP_MEMORIA");
  puerto_memoria = config_get_string_value(config, "PUERTO_MEMORIA");

  ip_cpu = config_get_string_value(config, "IP_CPU");
  puerto_cpu_dispatch = config_get_string_value(config, "PUERTO_CPU_DISPATCH");
  puerto_cpu_interrupt =
      config_get_string_value(config, "PUERTO_CPU_INTERRUPT");

  algoritmo_planificacion =
      config_get_string_value(config, "ALGORITMO_PLANIFICACION");
  if (strcmp(algoritmo_planificacion, "fifo") != 0 &&
      strcmp(algoritmo_planificacion, "rr") != 0 &&
      strcmp(algoritmo_planificacion, "vr") != 0)
    exit_config_field_error(logger, "ALGORITMO_PLANIFICACION");

  initial_quantum = config_get_int_value(config, "QUANTUM");
  instancias_recursos = config_get_array_value(config, "INSTANCIAS_RECURSOS");
  recursos = config_get_array_value(config, "RECURSOS");
  grado_multiprogramacion =
      config_get_int_value(config, "GRADO_MULTIPROGRAMACION");
  path_instrucciones = config_get_string_value(config, "PATH_INSTRUCCIONES");

  new_queue = queue_create();
  ready_queue = queue_create();
  exec = NULL;
  blocked = list_create();
  finished = list_create();

  io_dict = dictionary_create();

  pthread_t console_thread;
  pthread_t scheduler_thread;

  pthread_mutex_init(&mutex_new, NULL);
  pthread_mutex_init(&mutex_ready, NULL);
  pthread_mutex_init(&mutex_blocked, NULL);
  pthread_mutex_init(&mutex_exec, NULL);
  pthread_mutex_init(&mutex_finished, NULL);
  pthread_mutex_init(&mutex_multiprogramacion, NULL);
  pthread_mutex_init(&mutex_algoritmo_planificacion, NULL);
  pthread_mutex_init(&mutex_io_dict, NULL);
  pthread_mutex_init(&mutex_scheduler, NULL);

  sem_init(&sem_ready_full, 1, 0);
  sem_init(&sem_ready_empty, 1, grado_multiprogramacion);
  sem_init(&sem_new_full, 1, 0);
  sem_init(&sem_exec_full, 1, 0);
  sem_init(&sem_exec_empty, 1, 1);
  sem_init(&sem_scheduler, 1, 0);

  int server_socket = connection_create_server(puerto_escucha);
  if (server_socket == -1)
    exit_server_connection_error(logger);
  log_info(logger, "Servidor levantado en el puerto %s", puerto_escucha);

  pthread_create(&console_thread, NULL, &consola_interactiva, NULL);
  pthread_create(&console_thread, NULL, &scheduler, NULL);
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

  pthread_join(console_thread, NULL);
  pthread_join(scheduler_thread, NULL);

  connection_close(server_socket);

  pthread_mutex_destroy(&mutex_new);
  pthread_mutex_destroy(&mutex_ready);
  pthread_mutex_destroy(&mutex_exec);
  pthread_mutex_destroy(&mutex_blocked);
  pthread_mutex_destroy(&mutex_finished);
  pthread_mutex_destroy(&mutex_io_dict);
  pthread_mutex_destroy(&mutex_multiprogramacion);
  pthread_mutex_destroy(&mutex_algoritmo_planificacion);
  pthread_mutex_destroy(&mutex_algoritmo_planificacion);

  sem_destroy(&sem_ready_empty);
  sem_destroy(&sem_ready_full);
  sem_destroy(&sem_new_full);
  sem_destroy(&sem_exec_full);
  sem_destroy(&sem_exec_empty);
  sem_destroy(&sem_scheduler);

  dictionary_destroy_and_destroy_elements(io_dict, &free_io);
  queue_destroy_and_destroy_elements(new_queue, (void *)&process_destroy);
  queue_destroy_and_destroy_elements(ready_queue, (void *)&process_destroy);
  list_destroy_and_destroy_elements(blocked, (void *)&queue_destroy);
  list_destroy_and_destroy_elements(finished, (void *)&process_destroy);

  log_destroy(logger);
  config_destroy(config);
  return EXIT_SUCCESS;
}
