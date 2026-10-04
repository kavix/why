#!/bin/env bash

_why(){
  # COMP_WORDs=(why dns ...)
  # COMP_CWORD=1
  # COMP_LINE = 'why dns ..' // the whole cmd as string
  # COMP_POINT=1 // index
  # COMPREPLY=(response array) // we need to complete it
  # COMP_WORDBREAKS=....advanced....

  COMPREPLY=()

  # get the input from the user
  local input=${COMP_WORDS[COMP_CWORD]}
  
  # subcommand completion
  if ((COMP_CWORD == 1));then 

    # get the list of all commands possible
    local commands=$(why completion list-commands bash)

    #filter this list based on user input
    COMPREPLY=(
      $(compgen -W "$commands" -- "$input")
    )
  fi
  # flags completion
  if [[ "$input" == -* ]];then 
    #get the list of all flags possible
    local flags=$(why completion list-flags bash)
    
    #filter this list based on user input
    COMPREPLY=(
      $(compgen -W "$flags" -- "$input")
    )
  fi
}

complete -F _why why
