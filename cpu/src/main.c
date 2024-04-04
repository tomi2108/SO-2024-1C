#include <utils/connection.h>
#include <utils/packet.h>
#include <utils/person.h>

int main(int argc, char *argv[]) {

  int fd_socket = connection_create_client("127.0.0.1", "3002");
  person_t person = {432, 12, 100, "Tomas Sanchez"};

  packet_t *packet = packet_create();
  person_pack(packet, person);

  packet_send(packet, fd_socket);

  packet_destroy(packet);
  return 0;
}
