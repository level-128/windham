#include "../../libsrc/srclib.c"

void kernel_keyring_init() {
   is_kernel_keyring_exist = false;
}

void mapper_keyring_add_disk_key(const uint8_t key[HASHLEN], uint8_t uuid[16], EncMetadata metadata, unsigned timeout) {
   print_error(_("Linux kernel key retension service has been disabled at compile time."));
}

void mapper_keyring_add_key(const uint8_t key[HASHLEN], uint8_t uuid[16]) {
   print_error(_("Linux kernel key retension service has been disabled at compile time."));
}

bool mapper_keyring_get_disk_serial(const uint8_t uuid[16], uint8_t key[HASHLEN]) {
   return false;
}