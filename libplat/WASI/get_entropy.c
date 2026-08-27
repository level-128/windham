#include <unistd.h>
#include <stdlib.h>

// Do NOT use EM_ASM( crypto.getRandomValues(new Uint8Array(Module.HEAPU8.buffer, ...)) )
// here: the Emscripten JS minifier renames the Module.HEAPU8 reference inside
// EM_ASM strings (e.g. to "f.Pa") while the exported binding keeps its literal
// name, leaving the reference undefined in optimized builds. libc getentropy()
// is implemented in the library glue and minifies consistently.
void fill_secure_random_bits(uint8_t *address, const size_t size) {
   size_t off = 0;
   while (off < size) {
      size_t chunk = size - off > 256 ? 256 : size - off;
      if (getentropy(address + off, chunk) != 0) abort();  // never continue with weak randomness
      off += chunk;
   }
}
