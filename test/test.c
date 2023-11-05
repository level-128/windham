//	Argon2 reference source code package - reference C implementations.
// Modified to adapt Windham
//
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

int main(int argc, char * argv[]){
	init_enclib("/dev/urandom");
	get_system_info();
	test_enclib();
	test_mapper(argc == 2 ? argv[1] : NULL);
	test_backend(argc == 2 ? argv[1] : NULL);

}