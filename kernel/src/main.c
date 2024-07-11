#include <commons/collections/dictionary.h>
#include <commons/collections/list.h>
#include <commons/collections/queue.h>
#include <commons/config.h>
#include <commons/log.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <utils/command.h>
#include <utils/connection.h>
#include <utils/exit.h>
#include <utils/file.h>
#include <utils/instruction.h>
#include <utils/io_type.h>
#include <utils/packet.h>
#include <utils/process.h>
#include <utils/status.h>

#define FILE_NAME_MAX_LENGTH 60
#define FILE_LINE_MAX_LENGTH 80

typedef enum {
  BLOCK_IO = 1,
  FINISH = 2,
  BLOCK_R = 3,
} interrupt;

typedef struct {
  int socket;
  io_type type;
  int queue_index;
  sem_t sem_queue_full;
  pthread_mutex_t mutex_queue;
} io;
t_dictionary *io_dict;
t_dictionary *resource_dict;

typedef struct {
  char *name;
  int instances;
  int queue_index;
  pthread_mutex_t mutex_queue;
} resource;

resource *resources_array;

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
int num_resources;
int grado_multiprogramacion;
char *path_instrucciones;

int next_pid = 0;
int is_scheduler_running = 0;
int interrupting = 0;

t_queue *new_queue;
t_queue *ready_queue;
process_t *exec = NULL;
t_list *blocked;
t_list *finished;
t_queue *vrr_aux_queue;

pthread_mutex_t mutex_io_dict;
pthread_mutex_t mutex_resource_dict;
pthread_mutex_t mutex_resources_array;
pthread_mutex_t mutex_multiprogramacion;
pthread_mutex_t mutex_scheduler;
pthread_mutex_t mutex_interrupting;

pthread_mutex_t mutex_new;
pthread_mutex_t mutex_ready;
pthread_mutex_t mutex_exec;
pthread_mutex_t mutex_blocked;
pthread_mutex_t mutex_finished;
pthread_mutex_t mutex_vrr_aux;

sem_t sem_ready_empty;
sem_t sem_ready_full;
sem_t sem_new_full;
sem_t sem_exec_full;
sem_t sem_exec_empty;

sem_t sem_scheduler;

uint32_t strtoui32(char *s, int *is_number) {
  *is_number = 1;
  for (int i = 0; i < strlen(s); i++) {
    if (!isdigit(s[i])) {
      *is_number = 0;
      break;
    }
  }

  return strtol(s, NULL, 10);
}

char *ui32tostr(uint32_t n) {
  int length = snprintf(NULL, 0, "%d", n);
  char *ret = malloc(length + 1);
  snprintf(ret, length + 1, "%d", n);
  return ret;
}

void initialize_resources(char **recursos, char **instancias_recursos) {
  num_resources = 0;
  while (recursos[num_resources] != NULL)
    num_resources++;

  resources_array = malloc(num_resources * sizeof(resource));
  for (int i = 0; i < num_resources; i++) {
    int instances = atoi(instancias_recursos[i]);

    t_queue *io_queue = queue_create();
    pthread_mutex_lock(&mutex_blocked);
    int index = list_add(blocked, io_queue);
    pthread_mutex_unlock(&mutex_blocked);
    pthread_mutex_init(&resources_array[i].mutex_queue, NULL);

    resources_array[i].name = strdup(recursos[i]);
    resources_array[i].instances = instances;
    resources_array[i].queue_index = index;
  }
}

void free_resources(resource *resource_array) {
  for (int i = 0; i < num_resources; i++) {
    pthread_mutex_destroy(&resources_array[i].mutex_queue);
    free(resources_array[i].name);
    free(&resources_array[i]);
  }
}

void free_io(void *e) {
  io *interface = (io *)e;
  sem_destroy(&interface->sem_queue_full);
  pthread_mutex_destroy(&interface->mutex_queue);
  free(interface);
}

void print_process_queue(t_queue *queue, char *status) {
  if (queue_is_empty(queue)) {
    printf("[%s] empty\n", status);
    return;
  }

  process_t *head = queue_pop(queue);
  uint32_t head_pid = head->pid;
  process_print(*head, status);
  queue_push(queue, head);

  process_t *aux_process = queue_peek(queue);
  uint32_t aux_pid = aux_process->pid;

  while (aux_pid != head_pid) {
    aux_process = queue_pop(queue);
    process_print(*aux_process, status);
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

void send_to_ready(process_t *process) {
  pthread_mutex_lock(&mutex_ready);
  queue_push(ready_queue, process);
  pthread_mutex_unlock(&mutex_ready);
  sem_post(&sem_ready_full);
}

void send_to_vrr_aux(process_t *process) {
  pthread_mutex_lock(&mutex_vrr_aux);
  queue_push(vrr_aux_queue, process);
  pthread_mutex_unlock(&mutex_vrr_aux);
  sem_post(&sem_ready_full);
}

void send_vrr_aux_to_exec() {
  pthread_mutex_lock(&mutex_exec);
  pthread_mutex_lock(&mutex_vrr_aux);
  if (queue_size(vrr_aux_queue) > 0) {
    exec = queue_pop(vrr_aux_queue);
    log_info(logger, "Se envia el proceso %u a EXEC", exec->pid);
    pthread_mutex_unlock(&mutex_vrr_aux);
    pthread_mutex_unlock(&mutex_exec);
    sem_post(&sem_exec_full);
    return;
  }
  pthread_mutex_unlock(&mutex_vrr_aux);
  pthread_mutex_unlock(&mutex_exec);
}

int get_resource_id(char *resource) {
  int resource_i = -1;
  for (int i = 0; i < num_resources; i++) {
    pthread_mutex_lock(&mutex_resources_array);
    if (strcmp(resources_array[i].name, resource) == 0) {
      pthread_mutex_unlock(&mutex_resources_array);
      return i;
    }
    pthread_mutex_unlock(&mutex_resources_array);
  }

  return resource_i;
}

void *unblock_process_resource(void *arg) {
  char *resource_name = (char *)arg;
  int r_id = get_resource_id(resource_name);

  pthread_mutex_lock(&mutex_resources_array);
  resource r = resources_array[r_id];
  pthread_mutex_unlock(&mutex_resources_array);

  int blocked_queue_index = r.queue_index;
  pthread_mutex_lock(&mutex_blocked);
  t_queue *blocked_queue = list_get(blocked, blocked_queue_index);
  pthread_mutex_unlock(&mutex_blocked);

  pthread_mutex_lock(&r.mutex_queue);
  if (queue_size(blocked_queue) == 0) {
    pthread_mutex_unlock(&r.mutex_queue);
    free(resource_name);
    return NULL;
  }
  process_t *unblocked_process = queue_pop(blocked_queue);
  pthread_mutex_unlock(&r.mutex_queue);

  send_to_ready(unblocked_process);
  log_info(logger, "Se envia el proceso %u de BLOCKED %s a READY",
           unblocked_process->pid, resource_name);
  free(resource_name);
  uint32_t *pid = malloc(sizeof(uint32_t));
  *pid = unblocked_process->pid;
  return pid;
}

void free_process_resources(uint32_t pid) {
  char *key = ui32tostr(pid);
  pthread_mutex_lock(&mutex_resource_dict);
  int *taken_resources = dictionary_get(resource_dict, key);
  pthread_mutex_unlock(&mutex_resource_dict);

  for (int i = 0; i < num_resources; i++) {
    int taken_instances = taken_resources[i];
    pthread_mutex_lock(&mutex_resources_array);
    resources_array[i].instances += taken_instances;
    while (taken_instances > 0 && resources_array[i].instances >= 0) {
      int name_length = strlen(resources_array[i].name);
      int name_size = sizeof(char) * (name_length + 1);
      char *name = malloc(name_size);
      memcpy(name, resources_array[i].name, name_size);
      pthread_mutex_unlock(&mutex_resources_array);
      uint32_t *unblocked_pid = unblock_process_resource(name);
      pthread_mutex_lock(&mutex_resources_array);
      if (unblocked_pid == NULL)
        break;
      char *unblocked_key = ui32tostr(*unblocked_pid);
      free(unblocked_pid);
      pthread_mutex_lock(&mutex_resource_dict);
      int *unblocked_taken_resources =
          dictionary_get(resource_dict, unblocked_key);
      pthread_mutex_unlock(&mutex_resource_dict);
      unblocked_taken_resources[i]++;
      resources_array[i].instances--;
      taken_instances--;
      free(unblocked_key);
    }
    pthread_mutex_unlock(&mutex_resources_array);
  }
  dictionary_remove_and_destroy(resource_dict, key, &free);
  free(key);
}

void free_process(uint32_t pid) {
  free_process_resources(pid);
  int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);
  packet_t *free_req = packet_create(FREE_PROCESS);
  packet_add_uint32(free_req, pid);
  packet_send(free_req, socket_memoria);
  packet_destroy(free_req);
  connection_close(socket_memoria);
}

void print_io_queue(char *name, void *value) {
  io *interfaz = (io *)value;
  pthread_mutex_lock(&mutex_blocked);
  t_queue *blocked_queue = list_get(blocked, interfaz->queue_index);
  pthread_mutex_unlock(&mutex_blocked);

  uint32_t queue_name_length = (9 + strlen(name)) * sizeof(char);
  char *queue_name = malloc(queue_name_length);
  memset(queue_name, 0, queue_name_length);
  strcat(queue_name, "BLOCKED ");
  strcat(queue_name, name);

  pthread_mutex_lock(&interfaz->mutex_queue);
  print_process_queue(blocked_queue, queue_name);
  pthread_mutex_unlock(&interfaz->mutex_queue);
  free(queue_name);
}

void list_processes(void) {
  pthread_mutex_lock(&mutex_new);
  print_process_queue(new_queue, "NEW");
  pthread_mutex_unlock(&mutex_new);

  pthread_mutex_lock(&mutex_ready);
  print_process_queue(ready_queue, "READY");
  pthread_mutex_unlock(&mutex_ready);

  pthread_mutex_lock(&mutex_exec);
  if (exec != NULL)
    process_print(*exec, "EXEC");
  else
    printf("[EXEC] empty\n");
  pthread_mutex_unlock(&mutex_exec);

  pthread_mutex_lock(&mutex_blocked);
  if (list_size(blocked) == 0) {
    pthread_mutex_unlock(&mutex_blocked);
    printf("[BLOCKED] empty\n");
  } else {
    pthread_mutex_unlock(&mutex_blocked);

    pthread_mutex_lock(&mutex_io_dict);
    if (dictionary_size(io_dict) > 0) {
      dictionary_iterator(io_dict, &print_io_queue);
      pthread_mutex_unlock(&mutex_io_dict);
    } else
      pthread_mutex_unlock(&mutex_io_dict);

    for (int i = 0; i < num_resources; i++) {
      pthread_mutex_lock(&mutex_resources_array);
      resource r = resources_array[i];
      pthread_mutex_unlock(&mutex_resources_array);

      pthread_mutex_lock(&mutex_blocked);
      t_queue *blocked_queue = list_get(blocked, r.queue_index);
      pthread_mutex_unlock(&mutex_blocked);

      uint32_t queue_name_length = (9 + strlen(r.name)) * sizeof(char);
      char *queue_name = malloc(queue_name_length);
      memset(queue_name, 0, queue_name_length);
      strcat(queue_name, "BLOCKED ");
      strcat(queue_name, r.name);

      pthread_mutex_lock(&resources_array[i].mutex_queue);
      print_process_queue(blocked_queue, queue_name);
      pthread_mutex_unlock(&resources_array[i].mutex_queue);
    }
  }

  pthread_mutex_lock(&mutex_finished);
  if (list_size(finished) == 0) {
    printf("[FINISHED] empty\n");
  }
  t_list_iterator *finished_iterator = list_iterator_create(finished);
  while (list_iterator_has_next(finished_iterator)) {
    process_t *finished_process = list_iterator_next(finished_iterator);
    process_print(*finished_process, "FINISHED");
  }
  pthread_mutex_unlock(&mutex_finished);
  list_iterator_destroy(finished_iterator);
};
void end_process(process_t *process, int was_new) {
  free_process(process->pid);
  log_info(logger, "Finaliza el proceso %u", process->pid);

  pthread_mutex_lock(&mutex_finished);
  list_add(finished, process);
  pthread_mutex_unlock(&mutex_finished);

  if (!was_new)
    sem_post(&sem_ready_empty);
}

void response_register_io(packet_t *request, int io_socket) {
  char *nombre = packet_read_string(request);
  char *tipo_interfaz = packet_read_string(request);

  log_info(logger, "Se conecto una interfaz de tipo %s y nombre %s",
           tipo_interfaz, nombre);

  io *interfaz = malloc(sizeof(io));
  interfaz->type = io_type_from_string(tipo_interfaz);
  free(tipo_interfaz);
  interfaz->socket = io_socket;
  t_queue *io_queue = queue_create();

  pthread_mutex_lock(&mutex_blocked);
  int index = list_add(blocked, io_queue);
  pthread_mutex_unlock(&mutex_blocked);

  interfaz->queue_index = index;
  sem_init(&interfaz->sem_queue_full, 1, 0);
  pthread_mutex_init(&interfaz->mutex_queue, NULL);

  pthread_mutex_lock(&mutex_io_dict);
  dictionary_put(io_dict, nombre, interfaz);
  pthread_mutex_unlock(&mutex_io_dict);

  while (1) {
    sem_wait(&interfaz->sem_queue_full);

    pthread_mutex_lock(&interfaz->mutex_queue);
    process_t *head = queue_peek(io_queue);
    pthread_mutex_unlock(&interfaz->mutex_queue);
    packet_send(head->io_packet, io_socket);
    packet_destroy(head->io_packet);
    head->io_packet = NULL;

    packet_t *packet = packet_recieve(interfaz->socket);
    // io disconnected
    if (packet == NULL)
      break;

    pthread_mutex_lock(&interfaz->mutex_queue);
    int size = queue_size(io_queue);
    process_t *process = NULL;
    if (size != 0)
      process = queue_peek(io_queue);
    pthread_mutex_unlock(&interfaz->mutex_queue);

    // process terminated
    if (process == NULL || head->pid != process->pid)
      continue;

    status_code status = status_unpack(packet);
    if (status == OK) {

      pthread_mutex_lock(&interfaz->mutex_queue);
      process_t *blocked_process = queue_pop(io_queue);
      pthread_mutex_unlock(&interfaz->mutex_queue);

      if (strcmp(algoritmo_planificacion, "VRR") == 0) {
        send_to_vrr_aux(blocked_process);
        log_info(
            logger,
            "Se envia el proceso %u de BLOCKED %s a la cola auxiliar de VRR",
            blocked_process->pid, nombre);
        continue;
      }
      send_to_ready(blocked_process);
      log_info(logger, "Se envia el proceso %u de BLOCKED %s a READY",
               blocked_process->pid, nombre);
    }
  }
  log_warning(logger, "La I/O %s fue desconecatda", nombre);

  pthread_mutex_lock(&mutex_blocked);
  t_queue *blocked_queue = list_get(blocked, interfaz->queue_index);
  pthread_mutex_unlock(&mutex_blocked);

  pthread_mutex_lock(&interfaz->mutex_queue);
  while (queue_size(blocked_queue) > 0) {
    process_t *blocked_process = queue_pop(blocked_queue);
    log_error(logger,
              "Finaliza el proceso %u porque la I/O %s no es compatible o "
              "no esta conectada",
              blocked_process->pid, nombre);
    end_process(blocked_process, 0);
  }
  pthread_mutex_unlock(&interfaz->mutex_queue);

  pthread_mutex_lock(&mutex_blocked);
  list_remove(blocked, interfaz->queue_index);
  pthread_mutex_unlock(&mutex_blocked);

  pthread_mutex_lock(&mutex_io_dict);
  dictionary_remove_and_destroy(io_dict, nombre, &free_io);
  pthread_mutex_unlock(&mutex_io_dict);
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

void init_process(char *path) {
  status_code res_status = request_init_process(path);
  if (res_status == OK) {
    process_t *new_process =
        process_create(next_pid, strdup(path), initial_quantum);

    pthread_mutex_lock(&mutex_new);
    queue_push(new_queue, new_process);
    pthread_mutex_unlock(&mutex_new);

    char *key = ui32tostr(new_process->pid);

    int *initial_resources_instances = malloc(num_resources * sizeof(int));
    memset(initial_resources_instances, 0, num_resources * sizeof(int));

    pthread_mutex_lock(&mutex_resource_dict);
    dictionary_put(resource_dict, key, initial_resources_instances);
    pthread_mutex_unlock(&mutex_resource_dict);

    sem_post(&sem_new_full);

    log_info(logger, "Se crea el proceso %u en NEW", new_process->pid);
    next_pid++;
  } else if (res_status == NOT_FOUND) {
    log_warning(logger, "El archivo %s no existe", path);
  }
};

void block_process_io(char *io_name, process_t *process) {
  pthread_mutex_lock(&mutex_io_dict);
  io *interfaz = dictionary_get(io_dict, io_name);
  pthread_mutex_unlock(&mutex_io_dict);

  pthread_mutex_lock(&mutex_blocked);
  t_queue *blocked_queue = list_get(blocked, interfaz->queue_index);
  pthread_mutex_unlock(&mutex_blocked);

  pthread_mutex_lock(&interfaz->mutex_queue);
  queue_push(blocked_queue, process);
  pthread_mutex_unlock(&interfaz->mutex_queue);

  sem_post(&interfaz->sem_queue_full);
  log_info(logger, "Se envia el proceso %u a BLOCKED %s", process->pid,
           io_name);
}

void block_process_resource(char *resource_name, process_t *process) {
  int r_id = get_resource_id(resource_name);

  pthread_mutex_lock(&mutex_resources_array);
  resource r = resources_array[r_id];
  pthread_mutex_unlock(&mutex_resources_array);

  int blocked_queue_index = r.queue_index;
  pthread_mutex_lock(&mutex_blocked);
  t_queue *blocked_queue = list_get(blocked, blocked_queue_index);
  pthread_mutex_unlock(&mutex_blocked);
  pthread_mutex_lock(&r.mutex_queue);
  queue_push(blocked_queue, process);
  pthread_mutex_unlock(&r.mutex_queue);
  log_info(logger, "Se envia el proceso %u a BLOCKED %s", process->pid, r.name);
}

process_t *request_cpu_interrupt(int interrupt, int socket_cpu_dispatch) {
  pthread_mutex_lock(&mutex_interrupting);
  if (interrupting == 1 && interrupt == 0) {
    pthread_mutex_unlock(&mutex_interrupting);
    return NULL;
  }
  interrupting = 1;

  int socket_cpu_interrupt =
      connection_create_client(ip_cpu, puerto_cpu_interrupt);
  if (socket_cpu_interrupt == -1)
    exit_client_connection_error(logger);

  packet_t *req = packet_create(interrupt == 0 ? STATUS : INTERRUPT);
  packet_send(req, socket_cpu_interrupt);
  packet_destroy(req);
  connection_close(socket_cpu_interrupt);

  if (interrupt == 0) {
    interrupting = 0;
    pthread_mutex_unlock(&mutex_interrupting);
    return NULL;
  }
  if (socket_cpu_dispatch != -1) {
    packet_t *res = packet_recieve(socket_cpu_dispatch);
    process_t updated_process = process_unpack(res);
    process_t *p = process_dup(updated_process);

    pthread_mutex_lock(&mutex_exec);
    if (exec != NULL && exec->io_packet != NULL)
      p->io_packet = exec->io_packet;
    pthread_mutex_unlock(&mutex_exec);

    packet_destroy(res);
    pthread_mutex_unlock(&mutex_interrupting);
    return p;
  }

  pthread_mutex_unlock(&mutex_interrupting);
  return NULL;
}

void response_io_gen_sleep(packet_t *res, char *nombre) {
  packet_t *io_res = packet_create(REGISTER_IO);

  uint32_t tiempo_espera = packet_read_uint32(res);
  packet_add_uint32(io_res, tiempo_espera);

  pthread_mutex_lock(&mutex_exec);
  exec->io_packet = io_res;
  pthread_mutex_unlock(&mutex_exec);
}

void response_io_stdin(packet_t *res, char *nombre) {
  packet_t *io_res = packet_create(REGISTER_IO);

  uint32_t pid = packet_read_uint32(res);
  packet_add_uint32(io_res, pid);
  uint32_t size = packet_read_uint32(res);
  packet_add_uint32(io_res, size);
  uint32_t splits = packet_read_uint32(res);
  packet_add_uint32(io_res, splits);

  for (int i = 0; i < splits; i++) {
    uint32_t address = packet_read_uint32(res);
    uint32_t split_size = packet_read_uint32(res);
    packet_add_uint32(io_res, address);
    packet_add_uint32(io_res, split_size);
  }

  pthread_mutex_lock(&mutex_exec);
  exec->io_packet = io_res;
  pthread_mutex_unlock(&mutex_exec);
}

void response_io_stdout(packet_t *res, char *nombre) {
  packet_t *io_res = packet_create(REGISTER_IO);

  uint32_t pid = packet_read_uint32(res);
  packet_add_uint32(io_res, pid);
  uint32_t splits = packet_read_uint32(res);
  packet_add_uint32(io_res, splits);

  for (int i = 0; i < splits; i++) {
    uint32_t address = packet_read_uint32(res);
    uint32_t size = packet_read_uint32(res);
    packet_add_uint32(io_res, address);
    packet_add_uint32(io_res, size);
  }

  pthread_mutex_lock(&mutex_exec);
  exec->io_packet = io_res;
  pthread_mutex_unlock(&mutex_exec);
}

void response_io_fs_create(packet_t *res, char *nombre) {
  char *file_name = packet_read_string(res);
  uint32_t pid = packet_read_uint32(res);

  packet_t *io_res = packet_create(REGISTER_IO);
  instruction_op op = IO_FS_CREATE;

  packet_add(io_res, &op, sizeof(instruction_op));
  packet_add_string(io_res, file_name);
  packet_add_uint32(io_res, pid);

  pthread_mutex_lock(&mutex_exec);
  exec->io_packet = io_res;
  pthread_mutex_unlock(&mutex_exec);
}

process_t *response_resize(packet_t *res, int socket_cpu_dispatch,
                           interrupt *exit, char **name) {
  uint32_t pid = packet_read_uint32(res);
  uint32_t size = packet_read_uint32(res);

  packet_t *req = packet_create(RESIZE_PROCESS);
  packet_add_uint32(req, pid);
  packet_add_uint32(req, size);

  int client_socket = connection_create_client(ip_memoria, puerto_memoria);
  packet_send(req, client_socket);
  packet_destroy(req);

  packet_t *res_memoria = packet_recieve(client_socket);
  if (res_memoria->type == OUT_OF_MEMORY) {
    log_error(logger, "Finaliza el proceso %u por falta de memoria", pid);
    *exit = FINISH;
    packet_destroy(res_memoria);
    return request_cpu_interrupt(1, socket_cpu_dispatch);
  }
  packet_destroy(res_memoria);
  return NULL;
}
process_t *response_wait(packet_t *res, int socket_cpu_dispatch,
                         interrupt *exit, char **name) {
  char *resource_name = packet_read_string(res);
  int resource_i = get_resource_id(resource_name);

  pthread_mutex_lock(&mutex_resources_array);
  resource *r = &resources_array[resource_i];

  if (resource_i != -1) {
    pthread_mutex_lock(&mutex_exec);
    char *key = ui32tostr(exec->pid);
    pthread_mutex_unlock(&mutex_exec);

    pthread_mutex_lock(&mutex_resource_dict);
    int *taken_resources = dictionary_get(resource_dict, key);
    taken_resources[resource_i]++;
    pthread_mutex_unlock(&mutex_resource_dict);

    free(key);
    r->instances--;
    if (r->instances < 0) {
      *exit = BLOCK_R;
      *name = strdup(r->name);
      pthread_mutex_unlock(&mutex_resources_array);
      return request_cpu_interrupt(1, socket_cpu_dispatch);
    }
    pthread_mutex_unlock(&mutex_resources_array);
    return NULL;
  }
  *exit = FINISH;
  pthread_mutex_unlock(&mutex_resources_array);
  return request_cpu_interrupt(1, socket_cpu_dispatch);
}

process_t *response_signal(packet_t *res, interrupt *exit,
                           int socket_cpu_dispatch) {
  char *resource_name = packet_read_string(res);
  int resource_i = get_resource_id(resource_name);

  pthread_mutex_lock(&mutex_resources_array);
  resource *r = &resources_array[resource_i];

  if (resource_i != -1) {
    if (r->instances < 0) {
      pthread_t th;
      pthread_create(&th, NULL, &unblock_process_resource, resource_name);
      pthread_detach(th);
    }
    pthread_mutex_lock(&mutex_exec);
    char *key = ui32tostr(exec->pid);
    pthread_mutex_unlock(&mutex_exec);

    pthread_mutex_lock(&mutex_resource_dict);
    int *taken_resources = dictionary_get(resource_dict, key);
    pthread_mutex_unlock(&mutex_resource_dict);

    if (taken_resources[resource_i] == 0) {
      pthread_mutex_unlock(&mutex_resources_array);
      return NULL;
    }

    pthread_mutex_lock(&mutex_resource_dict);
    taken_resources[resource_i]--;
    pthread_mutex_unlock(&mutex_resource_dict);

    free(key);
    r->instances++;
    pthread_mutex_unlock(&mutex_resources_array);
    return NULL;
  }
  pthread_mutex_unlock(&mutex_resources_array);
  *exit = FINISH;
  return request_cpu_interrupt(1, socket_cpu_dispatch);
}

int is_io_compatible(char *name, instruction_op op) {
  pthread_mutex_lock(&mutex_io_dict);
  if (dictionary_has_key(io_dict, name)) {
    io *io = dictionary_get(io_dict, name);
    pthread_mutex_unlock(&mutex_io_dict);
    return io_type_is_compatible(io->type, op);
  }
  pthread_mutex_unlock(&mutex_io_dict);
  return 0;
}

process_t *response_io_call(instruction_op op, packet_t *res,
                            int socket_cpu_dispatch, char **name) {
  char *nombre = packet_read_string(res);
  *name = strdup(nombre);
  if (is_io_compatible(nombre, op)) {
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
    case IO_FS_CREATE:
      response_io_fs_create(res, nombre);
      break;
    default:
      break;
    }
    return request_cpu_interrupt(1, socket_cpu_dispatch);
  }
  return NULL;
}
process_t *wait_process_exec(int socket_cpu_dispatch, interrupt *exit,
                             char **name) {
  packet_t *res = packet_recieve(socket_cpu_dispatch);
  switch (res->type) {
  case INSTRUCTION: {
    instruction_op op = packet_read_uint32(res);
    if (!instruction_is_syscall(op)) {
      packet_destroy(res);
      return NULL;
    }
    if (instruction_is_io(op)) {
      process_t *exit_process =
          response_io_call(op, res, socket_cpu_dispatch, name);
      if (exit_process == NULL) {
        *exit = FINISH;
        pthread_mutex_lock(&mutex_exec);
        log_error(logger,
                  "Finaliza el proceso %u porque la I/O %s no es compatible o "
                  "no esta conectada",
                  exec->pid, *name);
        pthread_mutex_unlock(&mutex_exec);
        packet_destroy(res);
        return request_cpu_interrupt(1, socket_cpu_dispatch);
      }
      *exit = BLOCK_IO;
      packet_destroy(res);
      return exit_process;
    }
    switch (op) {
    case SIGNAL: {
      process_t *exit_process = response_signal(res, exit, socket_cpu_dispatch);
      packet_destroy(res);
      return exit_process;
    }
    case WAIT: {
      process_t *exit_process =
          response_wait(res, socket_cpu_dispatch, exit, name);
      packet_destroy(res);
      return exit_process;
    }
    case RESIZE: {
      process_t *exit_process =
          response_resize(res, socket_cpu_dispatch, exit, name);
      packet_destroy(res);
      return exit_process;
    }
    case EXIT: {
      *exit = FINISH;
      return request_cpu_interrupt(1, socket_cpu_dispatch);
    }
    default:
      return NULL;
    }
  }
  case PROCESS: {
    process_t updated_process = process_unpack(res);
    packet_destroy(res);
    *exit = FINISH;
    process_t *p = process_dup(updated_process);
    pthread_mutex_lock(&mutex_exec);
    if (exec != NULL && exec->io_packet != NULL)
      p->io_packet = exec->io_packet;
    pthread_mutex_unlock(&mutex_exec);
    return p;
  }
  default:
    return NULL;
  }
  return NULL;
}

void block_if_scheduler_off() {
  sem_wait(&sem_scheduler);
  sem_post(&sem_scheduler);
}

void exec_process(int socket_cpu_dispatch) {
  pthread_mutex_lock(&mutex_exec);
  packet_t *request = process_pack(*exec);
  pthread_mutex_unlock(&mutex_exec);
  packet_send(request, socket_cpu_dispatch);
  packet_destroy(request);
}

void send_new_to_ready() {
  pthread_mutex_lock(&mutex_new);
  process_t *p = queue_pop(new_queue);
  pthread_mutex_unlock(&mutex_new);

  send_to_ready(p);

  log_info(logger, "Se envia el proceso %u a READY", p->pid);
}

void send_ready_to_exec() {
  pthread_mutex_lock(&mutex_exec);
  pthread_mutex_lock(&mutex_ready);
  exec = queue_pop(ready_queue);
  log_info(logger, "Se envia el proceso %u a EXEC", exec->pid);
  pthread_mutex_unlock(&mutex_ready);
  pthread_mutex_unlock(&mutex_exec);
  sem_post(&sem_exec_full);
}

void empty_exec() {
  sem_wait(&sem_exec_full);
  pthread_mutex_lock(&mutex_exec);
  process_destroy(exec);
  exec = NULL;
  pthread_mutex_unlock(&mutex_exec);
  pthread_mutex_lock(&mutex_interrupting);
  interrupting = 0;
  pthread_mutex_unlock(&mutex_interrupting);
  sem_post(&sem_exec_empty);
}

void planificacion_vrr() {
  int socket_cpu_dispatch =
      connection_create_client(ip_cpu, puerto_cpu_dispatch);
  if (socket_cpu_dispatch == -1)
    exit_client_connection_error(logger);

  send_vrr_aux_to_exec();

  pthread_mutex_lock(&mutex_exec);
  if (exec == NULL) {
    pthread_mutex_unlock(&mutex_exec);
    send_ready_to_exec();
  } else
    pthread_mutex_unlock(&mutex_exec);

  pthread_mutex_lock(&mutex_exec);
  int quantum_left = exec->quantum <= 0 ? initial_quantum : exec->quantum;
  pthread_mutex_unlock(&mutex_exec);

  int end_timer = quantum_left;
  struct timespec start, end;

  clock_gettime(CLOCK_MONOTONIC_RAW, &start);
  exec_process(socket_cpu_dispatch);

  process_t *updated_process = NULL;
  interrupt exit = 0;
  char *name = NULL;

  while (updated_process == NULL) {
    if (end_timer <= 0)
      break;
    updated_process = wait_process_exec(socket_cpu_dispatch, &exit, &name);
    clock_gettime(CLOCK_MONOTONIC_RAW, &end);
    uint64_t d = (end.tv_sec - start.tv_sec) * 1000 +
                 (end.tv_nsec - start.tv_nsec) / (1000 * 1000);
    end_timer -= d;
    start = end;

    if (end_timer > 0 && updated_process == NULL) {
      request_cpu_interrupt(0, socket_cpu_dispatch);
    }
  }

  if (updated_process != NULL)
    updated_process->quantum = end_timer < 0 ? 0 : end_timer;

  block_if_scheduler_off();
  empty_exec();

  if (end_timer <= 0 && updated_process == NULL) {
    updated_process = request_cpu_interrupt(1, socket_cpu_dispatch);
    updated_process->quantum = end_timer < 0 ? 0 : end_timer;
    send_to_ready(updated_process);
    pthread_mutex_lock(&mutex_interrupting);
    interrupting = 0;
    pthread_mutex_unlock(&mutex_interrupting);
    log_info(logger, "Se envia el proceso %u a READY por fin de quantum",
             updated_process->pid);
  } else if (exit == FINISH) {
    end_process(updated_process, 0);
  } else if (exit == BLOCK_IO) {
    block_process_io(name, updated_process);
  } else if (exit == BLOCK_R) {
    block_process_resource(name, updated_process);
  }
  free(name);

  connection_close(socket_cpu_dispatch);
}

void planificacion_rr() {
  int socket_cpu_dispatch =
      connection_create_client(ip_cpu, puerto_cpu_dispatch);
  if (socket_cpu_dispatch == -1)
    exit_client_connection_error(logger);

  send_ready_to_exec();

  int quantum_left = initial_quantum;
  int end_timer = quantum_left;
  struct timespec start, end;

  clock_gettime(CLOCK_MONOTONIC_RAW, &start);
  exec_process(socket_cpu_dispatch);

  process_t *updated_process = NULL;
  interrupt exit = 0;
  char *name = NULL;

  while (updated_process == NULL) {
    if (end_timer <= 0)
      break;

    updated_process = wait_process_exec(socket_cpu_dispatch, &exit, &name);
    clock_gettime(CLOCK_MONOTONIC_RAW, &end);
    uint64_t d = (end.tv_sec - start.tv_sec) * 1000 +
                 (end.tv_nsec - start.tv_nsec) / (1000 * 1000);
    end_timer -= d;
    start = end;

    if (end_timer > 0 && updated_process == NULL)
      request_cpu_interrupt(0, socket_cpu_dispatch);
  }

  block_if_scheduler_off();
  empty_exec();

  if (end_timer <= 0 && updated_process == NULL) {
    updated_process = request_cpu_interrupt(1, socket_cpu_dispatch);
    send_to_ready(updated_process);
    pthread_mutex_lock(&mutex_interrupting);
    interrupting = 0;
    pthread_mutex_unlock(&mutex_interrupting);
    log_info(logger, "Se envia el proceso %u a READY por fin de quantum",
             updated_process->pid);
  } else if (exit == FINISH) {
    end_process(updated_process, 0);
  } else if (exit == BLOCK_IO) {
    block_process_io(name, updated_process);
  } else if (exit == BLOCK_R)
    block_process_resource(name, updated_process);

  free(name);
  connection_close(socket_cpu_dispatch);
}

void planificacion_fifo() {
  int socket_cpu_dispatch =
      connection_create_client(ip_cpu, puerto_cpu_dispatch);
  if (socket_cpu_dispatch == -1)
    exit_client_connection_error(logger);

  send_ready_to_exec();
  exec_process(socket_cpu_dispatch);

  process_t *updated_process = NULL;
  interrupt exit = 0;
  char *name = NULL;

  while (updated_process == NULL) {
    updated_process = wait_process_exec(socket_cpu_dispatch, &exit, &name);
    if (updated_process == NULL)
      request_cpu_interrupt(0, socket_cpu_dispatch);
  }

  block_if_scheduler_off();
  empty_exec();

  if (exit == FINISH)
    end_process(updated_process, 0);
  else if (exit == BLOCK_IO) {
    block_process_io(name, updated_process);
  } else if (exit == BLOCK_R)
    block_process_resource(name, updated_process);

  free(name);
  connection_close(socket_cpu_dispatch);
}

void *scheduler_helper() {
  while (1) {
    block_if_scheduler_off();

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

      pthread_mutex_lock(&mutex_multiprogramacion);
      send_new_to_ready();
      pthread_mutex_unlock(&mutex_multiprogramacion);

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
    block_if_scheduler_off();

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

      if (strcmp(algoritmo_planificacion, "FIFO") == 0)
        planificacion_fifo();
      else if (strcmp(algoritmo_planificacion, "RR") == 0)
        planificacion_rr();
      else if (strcmp(algoritmo_planificacion, "VRR") == 0)
        planificacion_vrr();

      pthread_mutex_lock(&mutex_scheduler);
      run = is_scheduler_running;
      pthread_mutex_unlock(&mutex_scheduler);
    }
  }
  pthread_join(helper, NULL);
}

void stop_scheduler(void) {
  if (is_scheduler_running == 0) {
    log_warning(logger, "El Scheduler ya fue detenido");
  } else {
    is_scheduler_running = 0;
    sem_wait(&sem_scheduler);
  }
}

void start_scheduler(void) {
  if (is_scheduler_running == 1) {
    log_warning(logger, "El Scheduler ya fue iniciado");
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

process_t *process_queue_find_and_remove(t_queue *queue, uint32_t pid) {
  if (queue_is_empty(queue))
    return NULL;

  process_t *head = queue_pop(queue);
  uint32_t head_pid = head->pid;
  if (head_pid == pid) {
    return head;
  }
  queue_push(queue, head);

  process_t *aux_process = queue_peek(queue);
  uint32_t aux_pid = aux_process->pid;
  process_t *ret_process = NULL;

  while (aux_pid != head_pid) {
    aux_process = queue_pop(queue);
    if (aux_process->pid == pid) {
      ret_process = aux_process;
    } else
      queue_push(queue, aux_process);
    aux_process = queue_peek(queue);
    aux_pid = aux_process->pid;
  }
  return ret_process;
}

void finish_process(uint32_t pid) {
  pthread_mutex_lock(&mutex_exec);
  if (exec != NULL && exec->pid == pid) {
    pthread_mutex_unlock(&mutex_exec);
    request_cpu_interrupt(1, -1);
    return;
  }
  pthread_mutex_unlock(&mutex_exec);

  bool cmp_process(void *arg) {
    process_t *p = (process_t *)arg;
    return p->pid == pid;
  }

  process_t *process = NULL;
  pthread_mutex_lock(&mutex_finished);
  if (list_size(finished) != 0)
    process = list_find(finished, &cmp_process);
  pthread_mutex_unlock(&mutex_finished);
  if (process != NULL) {
    log_warning(logger, "El proceso %u ya se encuentra finalizado", pid);
    return;
  }

  pthread_mutex_lock(&mutex_new);
  process = process_queue_find_and_remove(new_queue, pid);
  pthread_mutex_unlock(&mutex_new);
  if (process != NULL) {
    sem_wait(&sem_new_full);
    end_process(process, 1);
    return;
  }
  pthread_mutex_unlock(&mutex_new);

  pthread_mutex_lock(&mutex_ready);
  process = process_queue_find_and_remove(ready_queue, pid);
  pthread_mutex_unlock(&mutex_ready);
  if (process != NULL) {
    sem_wait(&sem_ready_full);
    end_process(process, 0);
    return;
  }

  t_list *ios = NULL;
  pthread_mutex_lock(&mutex_io_dict);
  if (dictionary_size(io_dict) != 0)
    ios = dictionary_elements(io_dict);
  pthread_mutex_unlock(&mutex_io_dict);

  if (ios != NULL) {
    t_list_iterator *iterator = list_iterator_create(ios);
    while (list_iterator_has_next(iterator)) {
      io *io = list_iterator_next(iterator);
      pthread_mutex_lock(&mutex_blocked);
      t_queue *blocked_queue = list_get(blocked, io->queue_index);
      pthread_mutex_unlock(&mutex_blocked);

      pthread_mutex_lock(&io->mutex_queue);
      if (queue_size(blocked_queue) > 0) {
        process = process_queue_find_and_remove(blocked_queue, pid);
        process_t *head = queue_peek(blocked_queue);
        pthread_mutex_unlock(&io->mutex_queue);

        if (process != NULL) {
          list_iterator_destroy(iterator);
          list_destroy(ios);
          if (head != NULL && process->pid != head->pid)
            sem_wait(&io->sem_queue_full);
          end_process(process, 0);
          return;
        }
      }
      pthread_mutex_unlock(&io->mutex_queue);
    }
    list_iterator_destroy(iterator);
    list_destroy(ios);
  }

  for (int i = 0; i < num_resources; i++) {
    pthread_mutex_lock(&mutex_resources_array);
    resource *r = &resources_array[i];
    pthread_mutex_unlock(&mutex_resources_array);

    pthread_mutex_lock(&mutex_blocked);
    t_queue *blocked_queue = list_get(blocked, r->queue_index);
    pthread_mutex_unlock(&mutex_blocked);

    pthread_mutex_lock(&r->mutex_queue);
    process = process_queue_find_and_remove(blocked_queue, pid);
    pthread_mutex_unlock(&r->mutex_queue);
    if (process != NULL) {
      end_process(process, 0);
      return;
    }
  }

  log_warning(logger, "No se encontro un proceso con pid %u", pid);
}

void print_dir(uint32_t dir) {
  int socket = connection_create_client(ip_memoria, puerto_memoria);
  packet_t *req = packet_create(READ_DIR);
  packet_add_uint32(req, dir);
  packet_add_uint32(req, 1);
  packet_add_uint32(req, 1);

  packet_send(req, socket);
  packet_destroy(req);

  packet_t *res = packet_recieve(socket);
  uint8_t byte = packet_read_uint8(res);
  log_debug(logger, "Address: %u , Content: %u", dir, byte);
}

void print_resources() {
  pthread_mutex_lock(&mutex_resources_array);
  for (int i = 0; i < num_resources; i++) {
    resource *r = &resources_array[i];
    log_debug(logger, "NAME: %s INSTANCES: %d", r->name, r->instances);
  }
  pthread_mutex_unlock(&mutex_resources_array);
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
  case PRINT_DIR:
    print_dir(*(uint32_t *)p.value);
    break;
  case PRINT_RESOURCES:
    print_resources();
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
    int is_number = 0;
    errno = 0;
    uint32_t n = strtoui32(token, &is_number);
    if (is_number && !errno) {
      uint32_t *number = malloc(sizeof(uint32_t));
      memcpy(number, &n, sizeof(uint32_t));
      p->type = NUMBER;
      p->value = number;
    } else {
      p->type = STRING;
      p->value = token;
    }
  }
  return op;
}

void exec_script(char *path) {
  char *full_path = file_concat_path(path_instrucciones, path);

  FILE *script_file = fopen(full_path, "r");
  if (script_file == NULL) {
    log_warning(logger, "No se encontro el archivo %s", full_path);
    return;
  }

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
      log_warning(logger, "%s is not a command", input);
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
  int server_socket = connection_create_server(puerto_escucha);
  if (server_socket == -1)
    exit_server_connection_error(logger);

  ip_memoria = config_get_string_value(config, "IP_MEMORIA");
  puerto_memoria = config_get_string_value(config, "PUERTO_MEMORIA");

  ip_cpu = config_get_string_value(config, "IP_CPU");
  puerto_cpu_dispatch = config_get_string_value(config, "PUERTO_CPU_DISPATCH");
  puerto_cpu_interrupt =
      config_get_string_value(config, "PUERTO_CPU_INTERRUPT");

  algoritmo_planificacion =
      config_get_string_value(config, "ALGORITMO_PLANIFICACION");
  if (strcmp(algoritmo_planificacion, "FIFO") != 0 &&
      strcmp(algoritmo_planificacion, "RR") != 0 &&
      strcmp(algoritmo_planificacion, "VRR") != 0)
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
  if (strcmp(algoritmo_planificacion, "VRR") == 0)
    vrr_aux_queue = queue_create();

  io_dict = dictionary_create();
  resource_dict = dictionary_create();

  pthread_t console_thread;
  pthread_t scheduler_thread;

  pthread_mutex_init(&mutex_new, NULL);
  pthread_mutex_init(&mutex_ready, NULL);
  pthread_mutex_init(&mutex_blocked, NULL);
  pthread_mutex_init(&mutex_exec, NULL);
  pthread_mutex_init(&mutex_finished, NULL);
  pthread_mutex_init(&mutex_multiprogramacion, NULL);
  pthread_mutex_init(&mutex_io_dict, NULL);
  pthread_mutex_init(&mutex_resource_dict, NULL);
  pthread_mutex_init(&mutex_resources_array, NULL);
  pthread_mutex_init(&mutex_scheduler, NULL);
  pthread_mutex_init(&mutex_interrupting, NULL);
  if (strcmp(algoritmo_planificacion, "VRR") == 0)
    pthread_mutex_init(&mutex_vrr_aux, NULL);

  sem_init(&sem_ready_full, 1, 0);
  sem_init(&sem_ready_empty, 1, grado_multiprogramacion);
  sem_init(&sem_new_full, 1, 0);
  sem_init(&sem_exec_full, 1, 0);
  sem_init(&sem_exec_empty, 1, 1);
  sem_init(&sem_scheduler, 1, 0);

  initialize_resources(recursos, instancias_recursos);

  pthread_create(&scheduler_thread, NULL, &scheduler, NULL);
  pthread_create(&console_thread, NULL, &consola_interactiva, NULL);
  log_info(logger, "Servidor levantado en el puerto %s", puerto_escucha);
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
  pthread_mutex_destroy(&mutex_resources_array);
  pthread_mutex_destroy(&mutex_resource_dict);
  pthread_mutex_destroy(&mutex_multiprogramacion);
  pthread_mutex_destroy(&mutex_interrupting);
  if (strcmp(algoritmo_planificacion, "VRR") == 0)
    pthread_mutex_destroy(&mutex_vrr_aux);

  sem_destroy(&sem_ready_empty);
  sem_destroy(&sem_ready_full);
  sem_destroy(&sem_new_full);
  sem_destroy(&sem_exec_full);
  sem_destroy(&sem_exec_empty);
  sem_destroy(&sem_scheduler);

  dictionary_destroy_and_destroy_elements(io_dict, &free_io);
  dictionary_destroy(resource_dict);
  free_resources(resources_array);
  queue_destroy_and_destroy_elements(new_queue, (void *)&process_destroy);
  queue_destroy_and_destroy_elements(ready_queue, (void *)&process_destroy);
  list_destroy_and_destroy_elements(blocked, (void *)&queue_destroy);
  list_destroy_and_destroy_elements(finished, (void *)&process_destroy);

  if (strcmp(algoritmo_planificacion, "VRR") == 0)
    queue_destroy_and_destroy_elements(vrr_aux_queue, (void *)&process_destroy);

  log_destroy(logger);
  config_destroy(config);
  return EXIT_SUCCESS;
}
