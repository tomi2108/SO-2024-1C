#include <utils/connection.h>
#include <utils/packet.h>
#include <utils/person.h>

int main(int argc, char *argv[]) {

  int server_socket = connection_create_server("3002");
  int client_socket = connection_accept_client(server_socket);

  packet_t *packet = packet_create();
  packettype_t packet_type = packet_recieve(packet, client_socket);
  connection_close(client_socket);
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
    return 1;
  }

  return 0;
}
