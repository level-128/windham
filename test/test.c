//	Copyright (C) <2023->  <W. Wang (level-128)>
//
//	This program is free software: you can redistribute it and/or modify
//	it under the terms of the GNU General Public License as published by
//	the Free Software Foundation, version 3 of the License
//
//	This program is distributed in the hope that it will be useful,
//	but WITHOUT ANY WARRANTY; without even the implied warranty of
//	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//	GNU General Public License for more details.
//
//	You should have received a copy of the GNU General Public License
//	along with this program.  If not, see <https://www.gnu.org/licenses/>.

#define _(x) x // not using gnu gettext

#include "test_enclib.c"

#include "test_backend.c"

#include "test_mapper.c"
#include "test_dynenc.c"

#include "../backend/bklibmain.c"

#include <windham_const.h>


int main(int argc, char * argv[]) {
  is_pid1 = false;

   is_running_as_root();
   init();

   if (argc < 2) {
      print_error_no_exit("Useage: <module> <device>. <module> is one of the 'enclib' 'mapper' 'backend' 'all'");
      exit(0);
   }
   char * device;
   if (argc == 2) {
      system("rm -f /tmp/windhamtest");
      system("dd if=/dev/zero of=/tmp/windhamtest bs=32576 count=128");
      device = "/tmp/windhamtest";
   } else {
      device = argv[2];
   }
	if (strcmp(argv[1], "all") == 0) {
		test_enclib();
		test_mapper(device);
		test_backend(device);
		test_dynenc(device);
	} else if (strcmp(argv[1], "enclib") == 0) {
		test_enclib();
	} else if (strcmp(argv[1], "mapper") == 0) {
		test_mapper(device);
	} else if (strcmp(argv[1], "backend") == 0) {
		test_backend(device);
	} else if (strcmp(argv[1], "dynenc") == 0) {
		test_dynenc(device);
	} else {
		print_error("wrong param, <module> is one of the 'all' 'enclib' 'mapper' 'backend'");
	}
   return 0;
}
