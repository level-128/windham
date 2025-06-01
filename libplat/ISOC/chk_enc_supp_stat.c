void action_new_check_crypt_support_status(const char * str) {
   char * crypto_list[] = {
      "aes-xts-plain64",
      "twofish-xts-plain64",
      "serpent-xts-plain64",
      "twofish-xts-plain64be",
      "aes-xts-plain64be",
      "serpent-xts-plain64be"};
   if (is_in_list(str, crypto_list) == -1) {
      print_error(_("Designated encryption mode \"%s\" cannot be used under ISO C mode. If you are certain that your target "
                    "device supports such mode, use Windham compiled for GNU/Linux system."), str);
   }
}