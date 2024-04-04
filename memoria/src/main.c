#include <commons/config.h>
#include <stdio.h>
#include <stdlib.h>
#include <utils/connection.h>
#include <utils/packet.h>
#include <utils/person.h>

void gestionar_cpu(char *puerto_escucha) {

  int server_socket = connection_create_server(puerto_escucha);
  int cpu_socket = connection_accept_client(server_socket);

  packet_t *packet = packet_create();
  packettype_t packet_type = packet_recieve(packet, cpu_socket);
  connection_close(cpu_socket);
  connection_close(server_socket);

  switch (packet_type) {

  case PERSON: {
    person_t person = person_unpack(packet);
    packet_destroy(packet);
    printf("%u, %u, %u, %s", person.dni, person.age, person.passport,
           person.name);
    fflush(stdout);
    free(person.name);
    break;
  };
  default:
    exit(1);
  }

  connection_close(cpu_socket);
  connection_close(server_socket);
}

int main(int argc, char *argv[]) {

  t_config *config = config_create("memoria.config");
  if (config == NULL)
    return 1;

  // config conexiones
  char *puerto_escucha = config_get_string_value(config, "PUERTO_ESCUCHA");

  // config del modulo
  int tam_memoria = config_get_int_value(config, "TAM_MEMORIA");
  int tam_pagina = config_get_int_value(config, "TAM_PAGINA");
  char *PATH_INSTRUCCIONES =
      config_get_string_value(config, "PATH_INSTRUCCIONES");
  int cantidad_entradas_tlb = config_get_int_value(config, "RETARDO_RESPUESTA");

  // prueba
  gestionar_cpu(puerto_escucha);

  config_destroy(config);
  return 0;
}
