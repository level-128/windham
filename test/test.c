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

#define ENCLIB_DEBUG

#include "test_enclib.c"
#include "test_backend.c"
#include "test_mapper.c"

int main(int argc, char * argv[]){
	print_enable = true;
	
	if (argc < 2){
		print_error("Useage: <module> <device>. <module> is one of the 'enclib' 'mapper' 'backend'");
	}
	
	init();
	if (strcmp(argv[1], "enclib") == 0) {
		test_enclib();
	} else if (strcmp(argv[1], "mapper") == 0){
		check_file(argv[2], true, false);
		test_mapper(argv[2]);
	} else if (strcmp(argv[1], "backend") == 0){
		check_file(argv[2], true, false);
		test_backend(argv[2]);
	} else {
		print_error("wrong param, <module> is one of the 'enclib' 'mapper' 'backend'");
	}
	
	
}