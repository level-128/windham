#include <emscripten.h>

void fill_secure_random_bits(uint8_t *address, const size_t size) {
    EM_ASM({
        crypto.getRandomValues(
            new Uint8Array(Module.HEAPU8.buffer, $0, $1));
    }, address, size);
}