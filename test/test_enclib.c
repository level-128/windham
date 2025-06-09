#include <string.h>
#include <windham_const.h>
#include <../libplat/loopctl.c>
#include <../libsrc/enclib.c>
#include <../libsrc/windhamtab.c>

#include "testutil.c"

void test_checkhead(char * device_) {
   Data data;
   // 170 = 0b10101010
   memset(&data, 170, sizeof(data));
   assert(check_head(&data));
   fill_secure_random_bits((uint8_t * )&data, sizeof(data));
   assert(check_head(&data));

   char  name[strlen(device_) + sizeof("mkfs.ext4") + 2];
   sprintf(name, "mkfs.ext4 %s", device_);
   system(name);

   exec_test_error_command("Open % --key=12347 --max-unlock-time=1 --dry-run");
}

void test_windhamtab() {

   char * windhamtab =
      "# <device: PATH= | UUID= | DEV= >  <to:>  <key: ASK | KEYFILE= | CLEVIS= >  <options:>  <pass>\n"
      "DEV=/dev/sdb1  encsdb1  ASK  systemd,readonly  1\n"
      "UUID=2f7d1c8c-7955-45cb-8b66-4071c34b1fcb  windham_home  KEYFILE=/home/keyfile none 2\n";
   char * filename = tmpnam(NULL);
   int fd = open(filename, O_RDWR | O_CREAT, 0777);
   if (write(fd, windhamtab, strlen(windhamtab)) == -1) {
      perror("write");
      exit(2);
   }
   close(fd);
   int entity_count;
   WindhamtabEntity * entities = parse_file(filename, &entity_count, false, 0);


}


void test_enclib(char * device_) {
   test_checkhead(device_);
}
