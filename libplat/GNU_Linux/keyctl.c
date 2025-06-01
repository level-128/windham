#include <stdint.h>
#include <dlfcn.h>
#include <keyutils.h>

#include "../../libsrc/srclib.c"
#include "../../include/windham_const.h"


key_serial_t (*p_add_key)(
   const char * type,
   const char * description,
   const void * payload,
   size_t       plen,
   key_serial_t ringid);

long (*p_keyctl_search)(
   key_serial_t ringid,
   const char * type,
   const char * description,
   key_serial_t destringid);

long (*p_keyctl_read)(key_serial_t id, char * buffer, size_t buflen);

long (*p_keyctl_set_timeout)(key_serial_t key, unsigned timeout);

long (*p_keyctl_setperm)(key_serial_t id, key_perm_t perm);

long (*p_keyctl)(int cmd, ...);

long (*p_keyctl_unlink)(key_serial_t id, key_serial_t ringid);


void kernel_keyring_init() {
   void * handle = dlopen("libkeyutils.so", RTLD_LAZY);
   if (handle == NULL) {
      is_kernel_keyring_exist = false;
      print_warning(
         _("libkeyutils.so could not be loaded, however, Windham is configured to enable Linux "
            "kernel key retension service support."));
   } else {
      is_kernel_keyring_exist = true;
      p_add_key               = dlsym(handle, "add_key");
      p_keyctl_search         = dlsym(handle, "keyctl_search");
      p_keyctl_read           = dlsym(handle, "keyctl_read");
      p_keyctl_setperm        = dlsym(handle, "keyctl_setperm");
      p_keyctl_set_timeout    = dlsym(handle, "keyctl_set_timeout");
      p_keyctl                = dlsym(handle, "keyctl");
      p_keyctl_unlink         = dlsym(handle, "keyctl_unlink");
   }
}

/**
 * @brief Adds a key to the Linux Keyring service.
 *
 * This function adds a key to the Linux Keyring service. The key is added only if
 * certain conditions are satisfied, such as the block size, encryption mode, and
 * start sector being equal to specific default values. If the key is successfully
 * added to the keyring, a timeout value is set for the key as well.
 *
 * @param key The key to be added, given as an array of bytes.
 * @param uuid The generated UUID for the key, represented as an array of bytes.
 * @param metadata
 * @param timeout The timeout value for the key.
 *
 * @return None.
 */
void mapper_keyring_add_disk_key(const uint8_t key[HASHLEN], uint8_t uuid[16], EncMetadata metadata, unsigned timeout) {
   if (! is_kernel_keyring_exist) {
      print_warning(
         _("Linux Kernel Keyring subsystem userspace module is missing. Some features (\"--timeout\") might not be supported. "
            "Please install \"libkeyutils.so\" using your package manager."));
   } else {
      printf(_("Registering the key into keyring with lifetime: %u sec.\n"), timeout);
   }
   bool is_ok_for_keyring = true;

   if (metadata.block_size != DEFAULT_BLOCK_SIZE) {
      print_warning(
         _("Cannot register the key into Linux Keyring service: The block size is not equal to the default value (%u), got (%u)."
         ),
         DEFAULT_BLOCK_SIZE,
         metadata.block_size);
      is_ok_for_keyring = false;
   }
   if (strcmp(metadata.enc_type, DEFAULT_DISK_ENC_MODE) != 0) {
      print_warning(
         _("Cannot register the key into Linux Keyring service: The encryption mode is not the same as the default (%s), got "
            "(%s). The default encryption mode may differ depending on the "
            "architecture. "),
         DEFAULT_DISK_ENC_MODE,
         metadata.enc_type);
      is_ok_for_keyring = false;
   }
   if (metadata.start_sector != WINDHAM_FIRST_USEABLE_LGA) {
      print_warning(
         _("Cannot register the key into Linux Keyring service: The start sector is not the same as the default value (%lu), got "
            "(%" PRIu64 ")."),
         WINDHAM_FIRST_USEABLE_LGA,
         metadata.start_sector);
      is_ok_for_keyring = false;
   }

   if (is_ok_for_keyring) {
      char name[strlen("windham_disk:") + 36 /* uuid len */ + 1];
      strcpy(name, "windham_disk:");
      generate_UUID_from_bytes(uuid, name + strlen("windham_disk:"));

      const key_serial_t key_serial = p_add_key("user", name, key, HASHLEN, KEY_SPEC_SESSION_KEYRING);

      if (key_serial < 0) {
         switch (errno) {
         case EDQUOT: {
            print_warning(
               _("Cannot register the key into Linux Keyring service: the key quota would be exceeded by creating this key "
                  "or linking it to the keyring."));
         }
         break;
         case EACCES: {
            print_warning(
               _("Cannot register the key into Linux Keyring service: the keyring wasn't available for modification. This "
                  "may be caused by SELinux or AppArmor policy."));
         }
         break;
         default: {
            perror("add_key()");
         };
         }
      }
      if (p_keyctl_setperm(key_serial, KEY_POS_SETATTR | KEY_USR_VIEW | KEY_USR_READ | KEY_USR_SEARCH) == -1) {
         if (errno == EACCES) {
            print_warning(
               _("Cannot register the key into Linux Keyring service: permission denied. This may be caused by SELinux or "
                  "AppArmor policy."));
         } else {
            perror("keyctl_setperm()");
         }
         p_keyctl_unlink(KEY_SPEC_SESSION_KEYRING, key_serial);
      }
      p_keyctl_set_timeout(key_serial, timeout);
   }
}

void mapper_keyring_add_key(const uint8_t key[HASHLEN], uint8_t uuid[16]) {
   if (! is_kernel_keyring_exist) {
      return;
   }
   char name[strlen("windham:") + 36 /* uuid len */ + 1];
   strcpy(name, "windham:");
   generate_UUID_from_bytes(uuid, name + strlen("windham:"));

   const key_serial_t key_serial = p_add_key("user", name, key, HASHLEN, KEY_SPEC_SESSION_KEYRING);

   if (key_serial < 0) {
      switch (errno) {
      case EDQUOT: {
         print_warning(
            _("Cannot register the key into Linux Keyring service: the key quota would be exceeded by creating this key "
               "or linking it to the keyring."));
      }
      break;
      case EACCES: {
         print_warning(
            _("Cannot register the key into Linux Keyring service: the keyring wasn't available for modification. This "
               "may be caused by SELinux or AppArmor policy."));
      }
      break;
      default: {
         perror("add_key()");
      };
      }
   }
   if (p_keyctl_setperm(key_serial, KEY_POS_SETATTR | KEY_USR_VIEW | KEY_USR_READ | KEY_USR_SEARCH) == -1) {
      if (errno == EACCES) {
         print_warning(
            _("Cannot register the key into Linux Keyring service: permission denied. This may be caused by SELinux or "
               "AppArmor policy."));
      } else {
         perror("keyctl_setperm()");
      }
      p_keyctl_unlink(KEY_SPEC_SESSION_KEYRING, key_serial);
   }
}


bool mapper_keyring_get_disk_serial(const uint8_t uuid[16], uint8_t key[HASHLEN]) {
   if (! is_kernel_keyring_exist) {
      return false;
   }
   char name[strlen("windham_disk:") + 36 /* uuid len */ + 1];
   strcpy(name, "windham_disk:");
   generate_UUID_from_bytes(uuid, name + strlen("windham_disk:"));

   key_serial_t key_serial = p_keyctl_search(KEY_SPEC_SESSION_KEYRING, "user", name, 0);
   if (key_serial < 0) {
      if (errno == ENOKEY) {
         return false;
      } else if (errno == EKEYREVOKED) {
         print_warning(_("The kernel keyring key has been removed."));
         p_keyctl_unlink(KEY_SPEC_SESSION_KEYRING, key_serial); // try to clear this, might fail but don't care
         return false;
      } else if (errno == EKEYEXPIRED) {
         print_warning(_("The kernel keyring key has expired."));
         p_keyctl_unlink(KEY_SPEC_SESSION_KEYRING, key_serial);
         return false;
      }
      perror("request_key");
      exit(1);
   }
   if (p_keyctl_read(key_serial, (char *) key, HASHLEN) == -1) {
      if (errno == EACCES) {
         print_warning(_("Cannot read key in keyring system. The key may have been modified."));
      }
      return false;
   }
   return true;
}