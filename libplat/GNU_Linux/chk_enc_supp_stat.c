#define MAX_LINE_LENGTH 1024
#define TARGET_PREFIX "name         : "


char ** get_crypto_list() {
   int     crypto_count = 0;
   char    line[MAX_LINE_LENGTH];
   char ** crypto_list = NULL;

   FILE * file = fopen("/proc/crypto", "r");
   if (file == NULL) {
      print_warning(
         _(
            "Cannot determine available encryption mode on the system. Please ensure that the kernel encryption subsystem is available."
         ));
      return NULL;
   }

   while (fgets(line, sizeof(line), file)) {
      if (strncmp(line, TARGET_PREFIX, strlen(TARGET_PREFIX)) == 0) {
         const char * name = line + strlen(TARGET_PREFIX);
         if (*name != '_' && strcmp("stdrng\n", name) != 0) {
            (crypto_count) ++;
            // ReSharper disable once CppDFAMemoryLeak
            crypto_list = realloc(crypto_list, sizeof(char *) * crypto_count);

            crypto_list[crypto_count - 1] = strdup(name);

            char * end = crypto_list[crypto_count - 1] + strlen(crypto_list[crypto_count - 1]) - 1;
            if (*end == '\n') {
               *end = '\0';
            }
         }
      }
   }
   crypto_list               = realloc(crypto_list, sizeof(char *) * (crypto_count + 1));
   crypto_list[crypto_count] = NULL;
   fclose(file);
   // ReSharper disable once CppDFAMemoryLeak
   return crypto_list;
}


void check_encryption_mode_arg(const char * str, int64_t idx[3]) {
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
      print_error(_("Invalid argument. Unrecognized cipher \"%s\". "), token);
   }

   token  = strtok(NULL, "-");
   idx[1] = is_in_list(token, chainmode_list);
   if (idx[1] == -1) {
      print_error(_("Invalid argument. Unrecognized chainmode \"%s\". "), token);
   }

   token  = strtok(NULL, "-");
   idx[2] = is_in_list(token, iv_list);
   if (idx[2] == -1) {
      print_error(_("Invalid argument. Unrecognized ivmode \"%s\". "), token);
   }
   free(strcpy);
}


void action_new_check_crypt_support_status(const char * str) {
   int64_t idx[3];
   check_encryption_mode_arg(str, idx);
   char ** crypto_list = get_crypto_list();

   if (crypto_list == NULL) {
      return;
   }

   char chainmode_name[32];
   sprintf(chainmode_name, "%s(%s)", chainmode_list[idx[1]], crypt_list[idx[0]]);
   if (is_in_list(chainmode_name, crypto_list) == -1) {
      ask_for_conformation(
         _(
            "The cipher %s you've requested might not be supported by your current system. Although you can create a "
            "header that employs this encryption scheme, "
            "your system might not be capable of unlocking it. This means you won't be able to access the encrypted "
            "device you've just created with this specific "
            "method on this system. You would need to locate a compatible system, recompile your kernel, or find the "
            "appropriate kernel module to access the "
            "device. Do you wish to proceed?"),
         chainmode_name);
   }

   for (int i = 0; crypto_list[i]; i ++) {
      free(crypto_list[i]);
   }
   free(crypto_list);
}