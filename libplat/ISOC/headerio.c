//
// Created by level on 25-5-20.
//
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "../../libsrc/srclib.c"

#define MAX(x, y) ((x) > (y) ? (x) : (y))

// Cache def


#ifndef CFG_ISOC_HEADERIO_CACHE_SIZE
#define CFG_ISOC_HEADERIO_CACHE_SIZE (1024 * 512)
#endif

// Don't put this under CFG_
#ifndef CACHE_LINE_CNT 
#define CACHE_LINE_CNT 8
#endif


// We usually do not need CACHE_LINE_CNT > 16, large caches are handled by OS.
// if CACHE_LINE_CNT <= 16, then hash table is slow. Use linear search
#if CACHE_LINE_CNT < 4 || CACHE_LINE_CNT > 16
#error "Cache system is not designed for such cache line count. Supported domain 4-16"
#endif

#define CACHE_SIZE (CFG_ISOC_HEADERIO_CACHE_SIZE / CACHE_LINE_CNT)


typedef struct {
   uintptr_t cache_start[CACHE_LINE_CNT];
   uintmax_t visit_count[CACHE_LINE_CNT]; // it is impossible to overflow uintmax_t if it ++ per miss.
   uint8_t cache_content[CACHE_LINE_CNT][CACHE_SIZE];
} HeaderCache;

/* ── Platform device I/O (stdio FILE *) ────────────────────── */
/* On 32-bit platforms long is only 32-bit, so fseek(long, SEEK_SET)
   cannot represent offsets beyond 2 GiB.  We wrap the FILE * in a
   small struct that tracks the absolute byte offset and uses
   fseek(SEEK_CUR) in multiple steps when the delta exceeds LONG_MAX.*/

struct device_handle {
	FILE    *fp;
	uint64_t offset;   /* current absolute byte position */
   HeaderCache * cache;
   uint64_t cur_visit_count;
};



// This cache is only designed for 4K IOPS bounded, not seq speed bounded.
// libc has very thick abstrations, on most implementations, it has some sort of buf. 
// enable only you are not running on an OS, or your env has no buf.
#ifndef CFG_ISOC_HEADERIO_ENABLE_CACHE
HeaderCache * cache_init(){
   return NULL;
}
#else
HeaderCache * cache_init(){
   HeaderCache * cache = calloc(1, sizeof(HeaderCache));
   // when calloc failed, fallback to no cache.
   for (int i = 0; i < CACHE_LINE_CNT && cache; i++){
      cache->cache_start[i] -= 1; // no disk will seek this poz.
   }
}
#endif



typedef struct {
   int start_cache_line;
   int end_cache_line;
   int last_used_cache;
   int last2_used_cache;
} BufContainsRet;

/* off: FILE byte offset.  Finds which cache lines (if any) cover
   the aligned windows touched by [off, off+size).  Returns the two
   least-recently-used lines for eviction (excluding hit lines). */
BufContainsRet buf_contains(struct device_handle *handle, uintptr_t off, size_t size){
   BufContainsRet ret = {-1, -1, 0, 1};
   uintmax_t smallest  = UINTMAX_MAX;
   uintmax_t smallest2 = UINTMAX_MAX;

   uintptr_t start_off = (off / CACHE_SIZE) * CACHE_SIZE;
   uintptr_t end_off   = ((off + size - 1) / CACHE_SIZE) * CACHE_SIZE;

   for (int i = 0; i < CACHE_LINE_CNT; i++){
      uintptr_t cs = handle->cache->cache_start[i];
      if (cs == start_off) {
         ret.start_cache_line = i;
         handle->cur_visit_count++;
         handle->cache->visit_count[i] = handle->cur_visit_count;
         if (end_off == start_off) ret.end_cache_line = i;
      } else if (end_off != start_off && cs == end_off) {
         ret.end_cache_line = i;
         handle->cur_visit_count++;
         handle->cache->visit_count[i] = handle->cur_visit_count;
      } else if (handle->cache->visit_count[i] < smallest) {
         smallest2 = smallest;
         smallest = handle->cache->visit_count[i];
         ret.last2_used_cache = ret.last_used_cache;
         ret.last_used_cache = i;
      } else if (handle->cache->visit_count[i] < smallest2) {
         smallest2 = handle->cache->visit_count[i];
         ret.last2_used_cache = i;
      }
   }
   return ret;
}

/* Core cache logic.  1) check case 1/2.  2) fill missing lines.
   3) re-check (now case 1 or 2) and copy.                            */
static bool cache_hit(struct device_handle *h, uint8_t *buf, size_t size) {
	if (!h->cache || size > CACHE_SIZE) return false;

	uintptr_t off       = h->offset;
	uintptr_t start_off = (off / CACHE_SIZE) * CACHE_SIZE;
	uintptr_t end_off   = ((off + size - 1) / CACHE_SIZE) * CACHE_SIZE;
	size_t    off_in    = (size_t)(off - start_off);

	BufContainsRet st = buf_contains(h, off, size);

retry:
	/* ── Case 1: single line fully covers ─────────────────── */
	if (st.start_cache_line != -1 &&
	    (st.start_cache_line == st.end_cache_line || start_off == end_off)) {
		memcpy(buf, h->cache->cache_content[st.start_cache_line] + off_in, size);
		h->offset += size;
		fseek(h->fp, (long)size, SEEK_CUR);
		return true;
	}

	/* ── Case 2: two lines, both present ──────────────────── */
	if (st.start_cache_line != -1 && st.end_cache_line != -1) {
		size_t first = CACHE_SIZE - off_in;
		if (first > size) first = size;
		memcpy(buf, h->cache->cache_content[st.start_cache_line] + off_in, first);
		memcpy(buf + first, h->cache->cache_content[st.end_cache_line], size - first);
		h->offset += size;
		fseek(h->fp, (long)size, SEEK_CUR);
		return true;
	}

	/* ── Fill missing lines, then retry ────────────────────── */
	int64_t saved = (int64_t)h->offset;

	if (st.start_cache_line == -1) {
		int t = st.last_used_cache;
		h->cache->cache_start[t] = start_off;
		h->cur_visit_count++;
		h->cache->visit_count[t] = h->cur_visit_count;
		device_seek(h, (int64_t)start_off);
		size_t nr = fread(h->cache->cache_content[t], 1, CACHE_SIZE, h->fp);
		h->offset = start_off + nr;
	}

	if (end_off != start_off && st.end_cache_line == -1) {
		int t = st.last2_used_cache;
		if (t == st.start_cache_line)
			for (int i = 0; i < CACHE_LINE_CNT; i++)
				if (i != t) { t = i; break; }
		h->cache->cache_start[t] = end_off;
		h->cur_visit_count++;
		h->cache->visit_count[t] = h->cur_visit_count;
		device_seek(h, (int64_t)end_off);
		size_t nr = fread(h->cache->cache_content[t], 1, CACHE_SIZE, h->fp);
		h->offset = end_off + nr;
	}

	/* Restore FILE to original position, then re-query */
	device_seek(h, saved);
	st = buf_contains(h, off, size);
	goto retry;
}



void *device_open(const char *path, bool writable) {
	struct device_handle *h = malloc(sizeof(*h));
	if (!h) {
      return NULL;
   }
	h->fp = fopen(path, writable ? "r+b" : "rb");
	if (!h->fp) { free(h); return NULL; }
	h->offset = 0;
   h->cur_visit_count = 0;
   h->cache = cache_init();
	return h;
}

void device_close(void *handle) {
	struct device_handle *h = handle;
	if (h) { fclose(h->fp); free(h); }
}

int device_seek(void *handle, int64_t offset) {
	struct device_handle *h = handle;
	int64_t delta = offset - (int64_t)h->offset;
	if (delta == 0) return 0;

	/* Step in LONG_MAX chunks via SEEK_CUR so the cast to long
	   never overflows, even on 32-bit platforms.               */
	while (delta > 0) {
		long step = delta > LONG_MAX ? LONG_MAX : (long)delta;
		if (fseek(h->fp, step, SEEK_CUR) != 0) return -1;
		delta -= step;
	}
	while (delta < 0) {
		long step = delta < LONG_MIN ? LONG_MIN : (long)delta;
		if (fseek(h->fp, step, SEEK_CUR) != 0) return -1;
		delta -= step;
	}
	h->offset = (uint64_t)offset;
	return 0;
}
int64_t device_read(void *handle, void *buf, size_t count) {
	struct device_handle *h = handle;
	if (h->cache && cache_hit(h, (uint8_t *)buf, count))
		return (int64_t)count;

	int64_t n = (int64_t)fread(buf, 1, count, h->fp);
	h->offset += (uint64_t)n;
	return n;
}

int64_t device_write(void *handle, const void *buf, size_t count) {
	struct device_handle *h = handle;
	int64_t n = (int64_t)fwrite(buf, 1, count, h->fp);
	if (n > 0) {
		uint64_t w_start = h->offset;
		h->offset += (uint64_t)n;
		/* Invalidate cache lines overlapping the write */
		if (h->cache) {
			uint64_t w_end = h->offset;
			for (int i = 0; i < CACHE_LINE_CNT; i++) {
				uintptr_t cs = h->cache->cache_start[i];
				if (cs != (uintptr_t)-1 &&
				    cs < w_end && cs + CACHE_SIZE > w_start)
					h->cache->cache_start[i] = (uintptr_t)-1;
			}
		}
	}
	return n;
}


void operate_header_on_device(Data *data, const char *device, int64_t offset, bool is_read) {
   assert(offset % 4 == 0);
   void *handle = device_open(device, is_read ? false : true);
   if (!handle) {
      print_error(_("Failed to open %s: %s"), device, strerror(errno));
      return;
   }

   struct device_handle *h = handle;
   if (setvbuf(h->fp, NULL, _IONBF, 0) != 0) {
      print_error(_("Failed to set buffer mode for %s: %s"), device, strerror(errno));
      device_close(handle);
      return;
   }

   if (device_seek(handle, offset) != 0) {
      print_error(_("Failed to seek in %s: %s"), device, strerror(errno));
      device_close(handle);
      return;
   }

   int64_t result;
   if (is_read) {
      result = device_read(handle, data, sizeof(Data));
   } else {
      result = device_write(handle, data, sizeof(Data));
   }
   if (result != (int64_t)sizeof(Data)) {
      if (is_read)
         print_error(_("Failed to read %s: %s"), device, strerror(errno));
      else
         print_error(_("Failed to write %s: %s"), device, strerror(errno));
   }

   device_close(handle);
}

void operate_aux_zone_on_device(uint8_t *aux_zone, size_t aux_zone_size, const char *device, int64_t offset, bool is_read) {
   void *handle = device_open(device, is_read ? false : true);
   if (!handle) {
      print_error(_("Failed to open %s for aux zone: %s"), device, strerror(errno));
      return;
   }

   struct device_handle *h = handle;
   if (setvbuf(h->fp, NULL, _IONBF, 0) != 0) {
      print_error(_("Failed to set buffer mode for %s: %s"), device, strerror(errno));
      device_close(handle);
      return;
   }

   if (device_seek(handle, offset) != 0) {
      print_error(_("Failed to seek aux zone on %s: %s"), device, strerror(errno));
      device_close(handle);
      return;
   }

   int64_t result;
   if (is_read) {
      result = device_read(handle, aux_zone, aux_zone_size);
   } else {
      result = device_write(handle, aux_zone, aux_zone_size);
   }
   if (result != (int64_t)aux_zone_size) {
      print_error(_("Failed to %s aux zone on %s: %s"),
                  is_read ? "read" : "write", device, strerror(errno));
   }
   device_close(handle);
}