# Access is controlled by socket permissions, not a shared loopback address.
bind_socket = "/run/rspamd/controller.sock mode=0660";
