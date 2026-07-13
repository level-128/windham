void action_new_check_crypt_support_status(const char * str) {
   int result = try_create_crypt_mapping(STR_device->name, str, "tmpchk");
   if (result == EMOBJ_try_create_crypt_mapping_FAILED_INIT) {
      print_warning(_("encryption compatibility test failed: driver could not be initialized."));
   } else if (result == EMOBJ_try_create_crypt_mapping_FAILED_MAPPING) {
      print_warning(_("Designate encryption mode \"%s\" is uncommon and not recommended. It might not be "
                       "supported under the target system. Windham recommends " DEFAULT_DISK_ENC_MODE "."), str);
   }
}