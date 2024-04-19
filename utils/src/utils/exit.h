#ifndef UTILS_EXIT_H_
#define UTILS_EXIT_H_

#include <commons/log.h>
#include <stdlib.h>

#define EXIT_SUCCESS 0
#define EXIT_SERVER_CONNECTION_ERROR 1
#define EXIT_CLIENT_CONNECTION_ERROR 2
#define EXIT_MALFORMATTED_CONFIG 3
#define EXIT_NOT_ENOUGH_ARGUMENTS 4
#define EXIT_MALFORMATTED_ARGUMENTS 5
#define EXIT_ENOENT 6
#define EXIT_CONFIG_FIELD_ERROR 7

void exit_success(t_log *logger);

void exit_server_connection_error(t_log *logger);

void exit_client_connection_error(t_log *logger);

void exit_malformatted_config_error(t_log *logger);

void exit_not_enough_arguments_error(t_log *logger);

void exit_malformatted_arguments_error(t_log *logger);

void exit_enoent_erorr(t_log *logger);

void exit_config_field_error(t_log *logger, char *field);

#endif
