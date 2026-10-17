# Rspamd runs unprivileged; only it and unoMail belong to the socket group.
bind_socket = "/run/rspamd/worker.sock mode=0660";
