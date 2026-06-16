#ifndef INCL_PROBELIB
#define INCL_PROBELIB

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "../include/windham_const.h"
#include "chkhead.c"


enum ProbeResultType {
    PROBE_RESULT_NONE = 0,
    PROBE_RESULT_SHEBANG,
    PROBE_RESULT_MAGIC,
    PROBE_RESULT_SUSPEND,
    PROBE_RESULT_ENTROPY,
};


/* ── read the Data header from a device path, return true on success ── */

static bool probe_read_header(const char *device_path, Data *out) {
	memset(out, 0, sizeof(Data));

	FILE *fp = fopen(device_path, "rb");
	if (!fp) return false;
	size_t n = fread(out, sizeof(Data), 1, fp);
	fclose(fp);
	return n == 1;
}


/* ── probe a single device; returns true if windham or encrypted, fills uuid and type ── */

bool probe_single_device(const char *device_path, uint8_t out_uuid[16], int *out_type) {
	Data buf;
	if (!probe_read_header(device_path, &buf)) {
		memset(out_uuid, 0, 16);
		if (out_type) *out_type = PROBE_RESULT_NONE;
		return false;
	}
	if (memcmp(&buf, (uint8_t[sizeof(Data)]){0}, sizeof(Data)) == 0) {
		memset(out_uuid, 0, 16);
		if (out_type) *out_type = PROBE_RESULT_NONE;
		return false;
	}

	if (memcmp(buf.head, shebang_line, sizeof(shebang_line)) == 0) {
		memcpy(out_uuid, buf.uuid_and_salt, 16);
		if (out_type) *out_type = PROBE_RESULT_SHEBANG;
		return true;
	}
	if (memcmp(buf.hint.windham_partition_magic_area,
	           windham_partition_magic,
	           sizeof(windham_partition_magic)) == 0) {
		memcpy(out_uuid, buf.uuid_and_salt, 16);
		if (out_type) *out_type = PROBE_RESULT_MAGIC;
		return true;
	}
	if (memcmp(buf.hint.hint.hint_tag, suspend_hint_tag,
	           sizeof(buf.hint.hint.hint_tag)) == 0) {
		memcpy(out_uuid, buf.uuid_and_salt, 16);
		if (out_type) *out_type = PROBE_RESULT_SUSPEND;
		return true;
	}

	if (check_head(&buf)) {
		memcpy(out_uuid, buf.uuid_and_salt, 16);
		if (out_type) *out_type = PROBE_RESULT_ENTROPY;
		return true;
	}

	memset(out_uuid, 0, 16);
	if (out_type) *out_type = PROBE_RESULT_NONE;
	return false;
}


/* ── probe multiple devices, return UUIDs (all-zero for non-windham devices) ── */

uint8_t *probe_multiple_devices(const char *device_paths[], size_t device_count) {
	if (device_count == 0) return NULL;

	uint8_t *uuids = malloc(device_count * 16);
	if (!uuids) return NULL;

	for (size_t i = 0; i < device_count; i++) {
		probe_single_device(device_paths[i], uuids + i * 16, NULL);
	}

	return uuids;
}

#endif
