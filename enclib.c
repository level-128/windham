
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <memory.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>

#include "print.c"
#include "library/Argon2/argon2.h"

#define KEY_SLOT_COUNT 6
#define KEY_SLOT_EXP_MAX 16
#define HASHLEN 32
#define BASE_MEM_COST 10
#define PARALLELISM 1

#define DEFAULT_ENC_TARGET_TIME 0.75



#ifndef UINT8_MAX
#error "the program only supports platform with uint8_t defined"
#endif

int random_fd;

typedef struct __attribute__((packed)){
    uint8_t hash_salt[HASHLEN];
    uint8_t len_exp[KEY_SLOT_EXP_MAX][2];
    uint8_t key_mask[HASHLEN];
} Key_slot;

typedef struct __attribute__((packed)){
    uint8_t enc_type[32];
    bool key_slot_usage[KEY_SLOT_COUNT];
    time_t raw_creat_time;
    uint32_t payload_offset;
} Metadata;

typedef struct __attribute__((packed)){
    __attribute__((unused)) uint8_t  head[16]; // '\xe8' '\xb4' '\xb4' '\xe8' '\xb4' '\xb4' 'l' 'e' 'v' 'e' 'l' '-' '1' '2' '8' '!'
    char master_key_mask[32];
    Key_slot keys[KEY_SLOT_COUNT];
    Metadata metadata;
}Data;

#pragma once

void print_hex_array(const uint8_t *arr, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        printf("%02x ", arr[i]);
    }
    printf("\n");
}

void fill_secure_random_bits(void *address, size_t size) {
    ssize_t read_size = read(random_fd, address, size);
    if (read_size != (ssize_t)size) {
        print("IO error while reading /dev/urandom.");
        *((volatile int*)NULL) = 0; // generate core dump
    }
}

void generate_random_numbers(uint8_t x, uint8_t* a, uint8_t* b) {
    uint8_t rand = random();
    *a = x + (rand % x);
    *b = x - (rand % x);
}

uint64_t iter_mem_new(const Key_slot * key_slot, int_fast8_t new_count, const uint8_t pwd[HASHLEN]){

    uint64_t avg = (key_slot->len_exp[new_count][0] ^ pwd[new_count * 2]) + (key_slot->len_exp[new_count][1] ^ pwd[new_count * 2 + 1]);

    return ((avg / 2) << new_count);
}


void argon2id_calc(const uint32_t m_cost, const void* pwd, const void* salt, const size_t saltlen, void * hash){
    print("argon2id_calc m_cost:", m_cost, "pwd:", pwd, "salt:", salt, "saltlen:", saltlen);
    argon2id_hash_raw(1, m_cost, PARALLELISM, pwd, HASHLEN, salt, saltlen, hash, HASHLEN);

}

uint64_t argon2id_calc_key_one_step(const Key_slot * key_slot, int_fast8_t new_count, uint8_t pwd[HASHLEN], uint64_t max_mem_size){
    uint8_t hash[HASHLEN];
    uint64_t new_mem_size = iter_mem_new(key_slot, new_count, pwd);

    print("----- argon2id_calc_key_one_step", "new_count:", new_count, "target_mem_size:", new_mem_size);

    if ( new_mem_size <= max_mem_size){
        if (new_mem_size == 0){
            new_mem_size = BASE_MEM_COST;
        }
        argon2id_calc(new_mem_size, pwd, key_slot->hash_salt, sizeof(key_slot->hash_salt) + sizeof(key_slot->len_exp[new_count]) * new_count, hash);

        memcpy(pwd, hash, HASHLEN);
        return new_mem_size;
    }
    return 0;
}

bool argon2id_add_key_one_step(Key_slot * key_slot, int_fast8_t new_count, uint8_t pwd[HASHLEN], uint64_t target_mem_size) {
    print("----- argon2id_add_key_one_step", "new_count:", new_count, "target_mem_size:", target_mem_size);
    uint8_t x = 0, y = 0;
    uint8_t hash[HASHLEN];
    target_mem_size >>= new_count;

    if (target_mem_size != 0) {
        generate_random_numbers(target_mem_size, &x, &y);
        print("randnum:", target_mem_size, x, y);
    }
    x = x ^ pwd[new_count * 2];
    y = y ^ pwd[new_count * 2 + 1];
    key_slot->len_exp[new_count][0] = x;
    key_slot->len_exp[new_count][1] = y;

    target_mem_size <<= new_count;

    if (target_mem_size == 0) {
        target_mem_size = BASE_MEM_COST;
    }
    argon2id_calc(target_mem_size, pwd, key_slot->hash_salt,
                      sizeof(key_slot->hash_salt) + sizeof(key_slot->len_exp[new_count]) * new_count, hash);


    memcpy(pwd, hash, HASHLEN);
}

bool argon2id_calc_key_one_slot(Data * self, int slot, uint8_t pwd[HASHLEN], uint64_t max_mem_size, bool is_new_pw){
    uint64_t mem_size_calced_total = 0;
    uint8_t password_hash[HASHLEN]; // calculating hash in password_hash
    // initial hash
    argon2id_calc(BASE_MEM_COST, pwd, self->keys[slot].hash_salt, HASHLEN, password_hash);

    int_fast8_t i = 0;
    for (i; i < KEY_SLOT_EXP_MAX; i++){
        uint64_t new_mem_size = argon2id_calc_key_one_step(&self->keys[slot], i, password_hash,
                                                           max_mem_size - mem_size_calced_total);
        mem_size_calced_total += new_mem_size;
        if (new_mem_size == 0){ // exceeded max mem
            if (is_new_pw){
                argon2id_add_key_one_step(&self->keys[slot], i, password_hash, max_mem_size - mem_size_calced_total);
                i += 1;
                break;
            }
            return false;
        }
    }

    for (i; i < KEY_SLOT_EXP_MAX; i++){
        argon2id_add_key_one_step(&self->keys[slot], i, password_hash, 0);
    }
    memcpy(pwd, password_hash, HASHLEN);
    return true;
}


//
//
//int main() {
//    int fd = open("/dev/urandom", O_RDONLY);
//    if (fd == -1) {
//        return 1;
//    }
//
//    uint8_t hash[HASHLEN];
//
//
//    Data * my_data = malloc(sizeof(Data));
//
//
//    print("new pw:\n");
//    void * password =  calloc(HASHLEN, 1);
//    memcpy(password, "level-128", sizeof("level-128"));
//    argon2id_calc_key_one_slot(my_data, 0, password, 2000, true);
//    print_hex_array(password, HASHLEN);
//
//    print("load pw:\n");
//    password =  calloc(HASHLEN, 1);
//    memcpy(password, "level-128", sizeof("level-128"));
//    argon2id_calc_key_one_slot(my_data, 0, password, 2000, false);
//    print_hex_array(password, HASHLEN);
//
//
//
//}
