#include <commons/config.h>
#include <commons/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <utils/connection.h>
#include <utils/packet.h>
#include <utils/person.h>

t_log *logger;
t_config *config;

void *gestionar_escucha(void *args) {

  char *puerto_escucha = config_get_string_value(config, "PUERTO_ESCUCHA");
  int server_socket = connection_create_server(puerto_escucha);
  log_debug(logger, "Servidor levantado en el puerto %s", puerto_escucha);

  int cpu_socket = connection_accept_client(server_socket);

  packet_t *packet = packet_create(0);
  packet_type packet_type = packet_recieve(packet, cpu_socket);
  connection_close(cpu_socket);
  connection_close(server_socket);

  log_debug(logger, "El siguiente paquete me lo envio %d", packet->author);

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

  return args;
}

int main(int argc, char *argv[]) {

  if (argc < 2)
    return 1;

  config = config_create(argv[1]);
  if (config == NULL)
    return 2;

  logger = log_create("memoria.log", "MEMORIA", 1, LOG_LEVEL_DEBUG);

  int tam_memoria = config_get_int_value(config, "TAM_MEMORIA");
  int tam_pagina = config_get_int_value(config, "TAM_PAGINA");
  char *PATH_INSTRUCCIONES =
      config_get_string_value(config, "PATH_INSTRUCCIONES");
  int cantidad_entradas_tlb = config_get_int_value(config, "RETARDO_RESPUESTA");

  // prueba
  gestionar_escucha(NULL);

  log_destroy(logger);
  config_destroy(config);
  return 0;
}
