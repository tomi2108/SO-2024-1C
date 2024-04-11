#include <commons/config.h>
#include <commons/log.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <utils/connection.h>
#include <utils/packet.h>
#include <utils/status.h>

t_log *logger;
t_config *config;

status_code request_init_process(char *path) {
  char *puerto_memoria = config_get_string_value(config, "PUERTO_MEMORIA");
  char *ip_memoria = config_get_string_value(config, "IP_MEMORIA");

  int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);

  packet_t *packet = packet_create(INIT_PROCESS);
  packet_add_string(packet, strlen(path), path);
  packet_send(packet, socket_memoria);
  packet_destroy(packet);

  packet_t *res = packet_recieve(socket_memoria);
  uint8_t status_code = status_read_packet(res);

  connection_close(socket_memoria);
  return status_code;
}

void response_register_io(packet_t *request, int client_socket) {
  char *nombre = packet_read_string(request, NULL);
  char *tipo_interfaz = packet_read_string(request, NULL);

  log_info(logger, "Se conecto una interfaz de tipo %s y nombre %s",
           tipo_interfaz, nombre);

  packet_destroy(request);

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

  connection_close(client_socket);
  free(args);
}

void exec_script(void);

void init_process(void) {
  printf("Ingresar path al archivo de instrucciones\n");
  char *path;
  scanf("%s", path);
  status_code res_status = request_init_process(path);
  if (res_status == OK) {
    int pid;
    // crear pcb y agregar a la cola de new
    log_info(logger, "Se crea el proceso %d en NEW", pid);
  } else if (res_status == NOT_FOUND) {
    log_error(logger, "El archivo %s no existe", path);
  }
};

void end_process(void);

void stop_planner(void);

void start_planner(void);

void change_multiprogramming(void);

void list_processes(void);

void *consola_interactiva(void *args) {
  while (1) {
    printf("+------------------------------------------+\n");
    printf("| %-40s |\n", "1: Ejecutar script");
    printf("| %-40s |\n", "2: Iniciar proceso");
    printf("| %-40s |\n", "3: Finalizar proceso");
    printf("| %-40s |\n", "4: Detener planificacion");
    printf("| %-40s |\n", "5: Iniciar planificacion");
    printf("| %-40s |\n", "6: Cambiar grado de multiprogramacion");
    printf("| %-40s |\n", "7: Listar estados de procesos");
    printf("| %-40s |\n", "Otro: Terminar proceso");
    printf("+------------------------------------------+\n");
    int input = getchar();
    switch (input) {
    case 49:
      exec_script();
      break;
    case 50:
      init_process();
      break;
    case 51:
      end_process();
      break;
    case 52:
      stop_planner();
      break;
    case 53:
      start_planner();
      break;
    case 54:
      change_multiprogramming();
      break;
    case 55:
      list_processes();
      break;
    default:
      return args;
    }
  }
  return args;
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
  }

  // config conexiones
  char *puerto_cpu_dispatch =
      config_get_string_value(config, "PUERTO_CPU_DISPATCH");
  char *puerto_cpu_interrupt =
      config_get_string_value(config, "PUERTO_CPU_INTERRUPT");
  char *ip_cpu = config_get_string_value(config, "IP_CPU");

  // config del modulo
  char *algoritmo_planificacion =
      config_get_string_value(config, "ALGORITMO_PLANIFICACION");
  int quantum = config_get_int_value(config, "QUANTUM");
  int grado_multiprogramacion =
      config_get_int_value(config, "GRADO_MULTIPROGRAMACION");
  char **instancias_recursos =
      config_get_array_value(config, "INSTANCIAS_RECURSOS");
  char **recursos = config_get_array_value(config, "RECURSOS");

  char *puerto_escucha = config_get_string_value(config, "PUERTO_ESCUCHA");
  int server_socket = connection_create_server(puerto_escucha);

  log_info(logger, "Servidor levantado en el puerto %s", puerto_escucha);

  pthread_t *console_thread;
  pthread_create(console_thread, NULL, &consola_interactiva, NULL);

  while (1) {
    int client_socket = connection_accept_client(server_socket);
    pthread_t *thread;
    int *arg = malloc(sizeof(int));
    *arg = client_socket;
    pthread_create(thread, NULL, &atender_cliente, arg);
    pthread_detach(*thread);
  }

  pthread_join(*console_thread, NULL);
  connection_close(server_socket);
  log_destroy(logger);
  config_destroy(config);
  return 0;
}
