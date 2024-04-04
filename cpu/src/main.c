#include <commons/config.h>
#include <utils/connection.h>
#include <utils/packet.h>
#include <utils/person.h>

void gestionar_memoria(char *ip_memoria, char *puerto_memoria) {

  int socket_memoria = connection_create_client(ip_memoria, puerto_memoria);
  person_t person = {432, 12, 100, "Tomas Sanchez"};

  packet_t *packet = packet_create();
  person_pack(packet, person);
  packet_send(packet, socket_memoria);

  connection_close(socket_memoria);
  packet_destroy(packet);
}

void *gestionar_dispatch(void *args) {
  char *puerto_dispatch;

  int socket_dispatch = connection_create_server(puerto_dispatch);

  connection_close(socket_dispatch);
  return args;
}

void *gestionar_interrumpt(void *args) {

  char *puerto_interrumpt;
  int socket_interrumpt = connection_create_server(puerto_interrumpt);

  connection_close(socket_interrumpt);
  return args;
}

int main(int argc, char *argv[]) {

  t_config *config = config_create("cpu.config");
  if (config == NULL)
    return 1;

  // config conexiones
  char *ip_memoria = config_get_string_value(config, "IP_MEMORIA");
  char *puerto_memoria = config_get_string_value(config, "PUERTO_MEMORIA");
  char *puerto_dispatch =
      config_get_string_value(config, "PUERTO_ESCUCHA_DISPATCH");
  char *puerto_interrupt =
      config_get_string_value(config, "PUERTO_ESCUCHA_INTERRUPT");

  // config del modulo
  int cantidad_entradas_tlb =
      config_get_int_value(config, "CANTIDAD_ENTRADAS_TLB");
  char *algoritmo_tlb = config_get_string_value(config, "ALGORITMO_TLB");

  // prueba
  gestionar_memoria(ip_memoria, puerto_memoria);

  config_destroy(config);
  return 0;
}
