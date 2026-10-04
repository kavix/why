complete -c why -f

# Subcommands
complete -c why \
    -n "not __fish_seen_subcommand_from (why completion list-commands fish | string split \n | string split -f1 \t)" \
    -a "(why completion list-commands fish)"

# Flags
complete -c why \
    -n "string match -q -- '-*' (commandline -ct)" \
    -a "(why completion list-flags fish)"
