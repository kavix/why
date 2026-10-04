#!/bin/env zsh

#compdef why

_why() {
    local input=$words[$CURRENT]

    # Subcommand completion
    if (( CURRENT == 2 )); then
        local -a commands

        commands=(
            ${(f)"$(why completion list-commands zsh)"}
        )

        _describe 'command' commands
        return
    fi

    # Flag completion
    if [[ "$input" == -* ]]; then
        local -a flags

        flags=(
            ${(f)"$(why completion list-flags zsh)"}
        )

        _describe 'option' flags
        return
    fi
}
# registering the function
compdef _why why
