# @file
# @author First author <first@author.com>
# @author Second author <second@author.com>
# @maintainer First maintainer <first@maintainer.com>
# @maintainer Second maintainer <Second@maintainer.com>
# @license MIT License
# SPDX-License-Identifier: MIT License
# shellcheck disable=SC0001,SC0002

# @description This is description.
# This is description secont line.
# @warning This is warning
# This is warning second line.
# @note This is note.
# This is note second line.
# @example This is a first example.
# This is first example second line.
# @example
# This is a second example.
# This is first example second line.
# @option -a This is -a option.
# @option -b <var> This is option -b with argument.
# @option -c --clong  This is option -c or --clong.
# @option -d --dlong <var> This is optino -d or --dlong with an argument.
# @option -e --elong=<var> This is option -r or --elong but argument is separated by =
# @arg $1 This is first argument
# @arg [$2] This is optional second argument
# @arg [$@] This are optional further arguments.
# @stdin This is what is expected on stdin.
# @stdout This is stdout output of the function.
# @stderr This is stderr output of the function.
# @env ENV this function uses this environment varaible.
# @env ANOTHER_ENV This is another environmnet varaible that the function uses.
# @set RESULT This is a variable that the function sets.
# @set ANOTHER_RESULT This is another variable that the function sets.
# @require this function requires bash>=4.
# @exitcode This function exits with 0
# @return This function returns 1
# @exit is alternative spelling of @exitcode.
# shellcheck disable=SC0004,SC0005
# @see https://example.com
# @see This is another link to see.
function example() {}

