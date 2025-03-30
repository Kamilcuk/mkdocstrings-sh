
# @file script.sh
# @description this is the description
# @license this is the license
# SPDX-License-Identifier: GPL-2.0

# @description some variable
VARIABLE=1

# @section first

# @description another variable
: "${ANOTHER_VAR:=1}"

# @section second

# @description variable2
: ${VARIABLE2:=1}
# @description variable3
: "${VARIABLE3=1}"

# @endsection

# @description variable4
: ${VARIABLE3=1}

# @description This is a function
# @option -a <arg> do this
# @option -f do that
# @option -l --longarg <arg> do this
# @arg $1 first arg
# @arg $2 second arg
# @see func2
func() {}

# @section a section
# @description this is some section

# @description Communicate with L_proc.
# @option -i <str> Send string to stdin.
# @option -o <var> Assign stdout to this variable.
# @option -e <var> Assign stderr to this variable.
# @option -t <int> Timeout in seconds.
# @option -k Kill L_proc after communication.
# @option -v <var> Assign exitcode to this variable.
# @arg $1 L_proc variable
# @return 0 if communication was successful
L_proc_communicate() {}

# @endsection

# @description func3
# @description Copy associative dictionary
# Notice: the destination array is cleared.
# Much faster then L_asa_copy.
# Note: Arguments are in different order.
#
# !!! warning
#
#     This is a warning
#
# @arg $1 var Destination associative array
# @arg $2 =
# @arg $3 var Source associative array
# @see L_asa_copy
# @see L_asa_dump
# @see L_asa_from_declare
# @example
#   local -A map=([a]=b [c]=d)
#   local -A mapcopy=()
#   L_asa_assign mapcopy = map
# @see func3
function func3() {}

