// recommended crypt

char * crypt_list[]     = {"aes", "twofish", "serpent", "sm4", NULL};
char * chainmode_list[] = {"cbc", "xts", "ecb", NULL};
char * iv_list[]        = {"plain64", "plain64be", "essiv", "eboiv", NULL};


void check_encryption_mode_arg(const char * str, int64_t idx[3]) {
   bool is_crypto_okay = true;
   int dash_count = 0;
   for (int i = 0; str[i] != '\0'; i ++) {
      if (str[i] == '-') {
         dash_count ++;
      }
   }
   if (dash_count != 2) {
      print_error(_("Invalid argument. The encryption scheme should obey the format: \"*cipher*-*chainmode*-*ivmode*\""));
   }
   char * strcpy = strdup(str);

   char * token = strtok(strcpy, "-");
   idx[0]       = is_in_list(token, crypt_list);
   if (idx[0] == -1) {
      print_warning(_("Unrecognized cipher \"%s\". "), token);
      is_crypto_okay = false;
   }

   token  = strtok(NULL, "-");
   idx[1] = is_in_list(token, chainmode_list);
   if (idx[1] == -1) {
      print_warning(_("Unrecognized chainmode \"%s\". "), token);
      is_crypto_okay = false;
   }

   token  = strtok(NULL, "-");
   idx[2] = is_in_list(token, iv_list);
   if (idx[2] == -1) {
      print_warning(_("Unrecognized ivmode \"%s\". "), token);
      is_crypto_okay = false;
   }
   free(strcpy);
   if (is_crypto_okay == false) {
      print_warning(_("Designate encryption mode \"%s\" contains unknown/unrecommended cipher/chainmode/ivmode. "
                             "These patterns "
                             "might contain cryptography flaws, or it might not be widely supported under different "
                             "systems. Windham recommends " DEFAULT_DISK_ENC_MODE "."), str);
   }
}


void action_new_check_crypt_support_status(const char * str) {
   int64_t idx[3];
   check_encryption_mode_arg(str, idx);


   char tempfile[] = "/tmp/windham-temp-test-XXXXXX";

   int fd = mkstemp(tempfile);
   if (fd == -1){
      goto FAIL1;
   }

   if (write(fd, (uint8_t [4096]){0}, 4096) != 4096) {
      goto FAIL2;
   }

   close(fd);

   char * exec_dir[]     = {"/sbin", "/usr/sbin", "/bin", "/usr/bin", NULL};
   char * dup_stdout     = NULL;
   size_t dup_stdout_len = 0;
   int    exec_ret_val   = 0;

   bool success = exec_name(
      "losetup",
      exec_dir,
      -1,
      &dup_stdout,
      &dup_stdout_len,
      &exec_ret_val,
      NMOBJ_exec_name_wait_child | NMOBJ_exec_name_dup_stdout_only,
      "-f",
      "--show",
      tempfile,
      NULL);
   if (! success || exec_ret_val != 0) {
      free(dup_stdout);
      goto FAIL2;
   }

   dup_stdout[dup_stdout_len - 1] = 0;
   memcpy(STR_device->name, dup_stdout, dup_stdout_len - 1);
   STR_device->is_loop = true;
   STR_device->block_count = -1;
   STR_device->block_size = -1;
   free(dup_stdout);

   int result = try_create_crypt_mapping(STR_device->name, str);

   if (result == EMOBJ_try_create_crypt_mapping_FAILED_INIT) {
      print_warning(_("dm-crypt initialization failed: create device-mapper mapping failed. Windham "
                      "is unable to test encryption compatibility, and the current running system will fail to open "
                      "the header that you are currently creating."))
   } else if (result == EMOBJ_try_create_crypt_mapping_FAILED_MAPPING) {
         ask_for_conformation(
      _("dm-crypt failed using the test parameter. "
         "The cipher %s you've requested might not be supported by your current system. Although you can create a "
         "header that employs this encryption scheme, "
         "your system might not be capable of unlocking it. This means you won't be able to access the encrypted "
         "device you've just created with this specific "
         "method on this system. You would need to locate for a compatible kernel module or recompile the kernel to "
         "access the device. Do you wish to proceed?"),
      str);
   }

   remove(tempfile);
   return;

   FAIL2:
   close(fd);
   remove(tempfile);

   FAIL1:
   print_warning(_("Cannot create temp file for dm-crypt test: %s. Are you using Landlock?"), strerror(errno));
}