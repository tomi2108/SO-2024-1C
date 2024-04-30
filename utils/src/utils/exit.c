#include "exit.h"

void exit_success(t_log *logger) { exit(EXIT_SUCCESS); }

void exit_server_connection_error(t_log *logger) {
  log_error(logger, "EXIT CODE %d Imposible levantar el servidor",
            EXIT_SERVER_CONNECTION_ERROR);
  exit(EXIT_SERVER_CONNECTION_ERROR);
}

void exit_client_connection_error(t_log *logger) {
  log_error(logger, "EXIT CODE %d Imposible conectarse al servidor",
            EXIT_CLIENT_CONNECTION_ERROR);
  exit(EXIT_CLIENT_CONNECTION_ERROR);
}

void exit_malformatted_config_error(t_log *logger) {
  log_error(logger, "EXIT CODE %d Archivo de configuarcion mal formateado",
            EXIT_MALFORMATTED_CONFIG);
  exit(EXIT_MALFORMATTED_CONFIG);
}

void exit_not_enough_arguments_error(t_log *logger) {
  log_error(logger, "EXIT CODE %d Argumentos insuficientes",
            EXIT_NOT_ENOUGH_ARGUMENTS);
  exit(EXIT_NOT_ENOUGH_ARGUMENTS);
}

void exit_malformatted_arguments_error(t_log *logger) {
  log_error(logger, "EXIT CODE %d Argumentos mal formateados",
            EXIT_MALFORMATTED_ARGUMENTS);
  exit(EXIT_MALFORMATTED_ARGUMENTS);
}

void exit_enoent_error(t_log *logger, char *path) {
  log_error(logger, "EXIT CODE %d No se econtro el archivo o directorio: %s",
            EXIT_ENOENT, path);
  exit(EXIT_ENOENT);
}

void exit_config_field_error(t_log *logger, char *field) {
  log_error(
      logger,
      "EXIT CODE %d Ocurrio un error leyendo el campo %s de la configuracion",
      EXIT_CONFIG_FIELD_ERROR, field);
  exit(EXIT_CONFIG_FIELD_ERROR);
}
