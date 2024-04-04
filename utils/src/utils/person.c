#include "person.h"

packet_t *person_pack(packet_t *packet, person_t person) {
  packet->type = PERSON;
  packet_add_uint32(packet, person.dni);
  packet_add_uint8(packet, person.age);
  packet_add_uint32(packet, person.passport);
  packet_add_string(packet, strlen(person.name), person.name);

  return packet;
}

person_t person_unpack(packet_t *packet) {
  person_t person;
  uint32_t person_name_length;
  person.dni = packet_read_uint32(packet);
  person.age = packet_read_uint8(packet);
  person.passport = packet_read_uint32(packet);
  person.name = packet_read_string(packet, &person_name_length);
  return person;
}
