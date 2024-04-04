#include <commons/config.h>
#include <utils/connection.h>
#include <utils/packet.h>
#include <utils/person.h>

int main(int argc, char *argv[]) {

  if (argc < 2)
    return 1;

  t_config *config = config_create(argv[1]);
  if (config == NULL)
    return 2;

  // config conexiones
  char *puerto_escucha = config_get_string_value(config, "PUERTO_ESCUCHA");
  char *puerto_memoria = config_get_string_value(config, "PUERTO_MEMORIA");
  char *ip_memoria = config_get_string_value(config, "IP_MEMORIA");
  char *puerto_cpu_dispatch =
      config_get_string_value(config, "PUERTO_CPU_DISPATCH");
  char *puerto_cpu_interrupt =
      config_get_string_value(config, "PUERTO_CPU_INTERRUPT");
  char *ip_cpu = config_get_string_value(config, "IP_CPU");

  // confgi del modulo
  char *algoritmo_planificacion =
      config_get_string_value(config, "ALGORITMO_PLANIFICACION");
  int config_get_int_value(config, "QUANTUM");
  int config_get_int_value(config, "GRADO_MULTIPROGRAMACION");
  char **instancias_recursos =
      config_get_array_value(config, "INSTANCIAS_RECURSOS");
  char **recursos = config_get_array_value(config, "RECURSOS");

  config_destroy(config);
  return 0;
}
