#include <commons/collections/queue.h>
#include <commons/config.h>
#include <commons/log.h>
#include <ctype.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <utils/connection.h>
#include <utils/packet.h>
#include <utils/process.h>
#include <utils/status.h>

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

int next_pid = 1;
t_queue *new_queue;
t_queue *ready_queue;
process_t *exec;
t_list *finished;
// seran multiples colas
t_queue *blocked;

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
  if (socket_memoria == -1) {
    log_error(logger, "Imposible crear la conexion a la memoria");
    exit(4);
  }
  packet_t *packet = packet_create(INIT_PROCESS);
  packet_add_string(packet, path);
  packet_send(packet, socket_memoria);
  packet_destroy(packet);

  packet_t *res = packet_recieve(socket_memoria);
  uint8_t status_code = status_read_packet(res);
  packet_destroy(res);
  connection_close(socket_memoria);
  return status_code;
}

void response_register_io(packet_t *request, int io_socket) {
  char *nombre = packet_read_string(request);
  char *tipo_interfaz = packet_read_string(request);

  log_info(logger, "Se conecto una interfaz de tipo %s y nombre %s",
           tipo_interfaz, nombre);

  packet_t *res = packet_create(REGISTER_IO);
  packet_add_uint32(res, 2);
  packet_send(res, io_socket);
  packet_destroy(res);
  // guardar el socket de la I/O para responderle cuando sea necesario
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
  return 0;
}

void exec_script(void) {}

void init_process(void) {
  printf("Ingresar path al archivo de instrucciones\n");
  // a chequear
  char path[20];
  int c;
  while ((c = getchar()) != '\n' && c != EOF) {
  }

  fgets(path, 19, stdin);
  if (strlen(path) < 21) {
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
void stop_planner(void) {}
void start_planner(void) {}
void change_multiprogramming(void) {}

void list_processes(void) {
  print_process_queue(new_queue, "NEW");
  print_process_queue(ready_queue, "READY");
  // imprimir el resto de procsos
};

void request_exec_process(process_t process) {

  int socket_cpu_dispatch =
      connection_create_client(ip_cpu, puerto_cpu_dispatch);
  if (socket_cpu_dispatch == -1) {
    log_error(logger,
              "Imposible crear la conexion al servidor dispatch del cpu");
    exit(5);
  }

  packet_t *request = process_pack(process);
  packet_send(request, socket_cpu_dispatch);

  connection_close(socket_cpu_dispatch);
  packet_destroy(request);
}

void planificacion_fifo() {
  while (1) {
    // semaforos...
    if (exec == NULL && !queue_is_empty(ready_queue)) {
      process_t *process_to_exec = queue_pop(ready_queue);
      request_exec_process(*process_to_exec);
      exec = process_to_exec;
    }
  }
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
      printf("| %-40s |\n", "8: Salir");
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
      stop_planner();
      break;
    case '5':
      start_planner();
      break;
    case '6':
      change_multiprogramming();
      break;
    case '7':
      list_processes();
      break;
    default:
      break;
    }

  } while (input != '8');
  return 0;
}

int main(int argc, char *argv[]) {

  logger = log_create("kernel.log", "KERNEL", 1, LOG_LEVEL_DEBUG);
  if (argc < 2) {
    log_error(logger, "Especificar archivo de configuracion");
    return 1;
  }

  config = config_create(argv[1]);
  if (config == NULL) {
    log_error(logger, "Error al crear la configuracion");
    return 2;
  }

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

  int socket_cpu_interrupt =
      connection_create_client(ip_cpu, puerto_cpu_interrupt);
  if (socket_cpu_interrupt == -1) {
    log_error(logger,
              "Imposible crear la conexion al servidor interrupt del cpu");
  }
  // por ahora
  connection_close(socket_cpu_interrupt);

  new_queue = queue_create();
  ready_queue = queue_create();
  exec = NULL;

  int server_socket = connection_create_server(puerto_escucha);
  if (server_socket == -1) {
    log_error(logger, "Imposible levantar servidor");
    return 3;
  }
  log_info(logger, "Servidor levantado en el puerto %s", puerto_escucha);

  pthread_t console_thread;
  pthread_create(&console_thread, NULL, &consola_interactiva, NULL);

  while (1) {
    int client_socket = connection_accept_client(server_socket);
    pthread_t thread;
    int *arg = malloc(sizeof(int));
    *arg = client_socket;
    pthread_create(&thread, NULL, &atender_cliente, arg);
    pthread_detach(thread);
  }

  queue_destroy(new_queue);
  queue_destroy(ready_queue);
  pthread_join(console_thread, NULL);
  connection_close(server_socket);
  log_destroy(logger);
  config_destroy(config);
  return 0;
}
