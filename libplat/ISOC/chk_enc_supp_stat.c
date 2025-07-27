void action_new_check_crypt_support_status(const char * str) {
   char * crypto_list[] = {
      "aes-xts-plain64",
      "aes-xts-plain64be",
      "aes-cbc-essiv"};
   if (is_in_list(str, crypto_list) == -1) {
      print_warning(_("Designate encryption mode \"%s\" is uncommon and not recommended. It might not be supported"
                    " under the target system. Windham recommends " DEFAULT_DISK_ENC_MODE "."), str);
   }
}