
# @file script.sh
# @description this is the description
# @license this is the license
# SPDX-License-Identifier: GPL-2.0
# @author Kamil Cukrowski <kamilcukrowski at gmail.com>
# @maintainer Kamil Cukrowski <kamilcukrowski@gmail.com>

# some variable
VARIABLE=1

# Variable with default assignment
: "${ANOTHER_VAR:=1}"

# @description This is a function
# @option -a <arg> Do this
# @option -f Do that
# @option -l --longarg <arg> Do something else
# @arg $1 first arg
# @arg $2 second arg
# @arg $@ Additional arguments
# @see another_function
example_function() {}

# This is another example function
# @warning This is a warning
# @notice This is a notice
# @noargs
example_function() {}
