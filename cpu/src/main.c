#include <commons/config.h>
#include <commons/log.h>
#include <utils/connection.h>
#include <utils/packet.h>
#include <utils/person.h>

t_log *logger;
t_config *config;

void *gestionar_memoria(void *args) {

  char *ip_memoria = config_get_string_value(config, "IP_MEMORIA");
  char *puerto_memoria = config_get_string_value(config, "PUERTO_MEMORIA");

  int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);
  person_t person = {432, 12, 100, "Tomas Sanchez"};

  packet_t *packet = packet_create();
  person_pack(packet, person);
  packet_send(packet, socket_memoria);

  connection_close(socket_memoria);
  packet_destroy(packet);
  return args;
}

void *gestionar_dispatch(void *args) {
  char *puerto_dispatch =
      config_get_string_value(config, "PUERTO_ESCUCHA_DISPATCH");

  int socket_dispatch = connection_create_server(puerto_dispatch);

  connection_close(socket_dispatch);
  return args;
}

void *gestionar_interrumpt(void *args) {

  char *puerto_interrumpt =
      config_get_string_value(config, "PUERTO_ESCUCHA_INTERRUPT");
  int socket_interrumpt = connection_create_server(puerto_interrumpt);

  connection_close(socket_interrumpt);
  return args;
}

int main(int argc, char *argv[]) {

  if (argc < 2)
    return 1;

  config = config_create(argv[1]);
  if (config == NULL)
    return 2;

  logger = log_create("cpu.log", "CPU", 1, LOG_LEVEL_DEBUG);

  // config del modulo
  int cantidad_entradas_tlb =
      config_get_int_value(config, "CANTIDAD_ENTRADAS_TLB");
  char *algoritmo_tlb = config_get_string_value(config, "ALGORITMO_TLB");

  // prueba
  gestionar_memoria(NULL);

  log_destroy(logger);
  config_destroy(config);
  return 0;
}
