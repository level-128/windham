mkdir cmake-build-debug
cmake -DCMAKE_BUILD_TYPE=Debug -B cmake-build-debug
cd cmake-build-debug/
make -j
mv windham_debug ../a.out
mv compile_commands.json ../compile_commands.json

pkexec bash -c "chown root /home/level-128/CLionProjects/windham/a.out && chmod u+s /home/level-128/CLionProjects/windham/a.out"
