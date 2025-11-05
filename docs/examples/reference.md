# Reference

Documentation consists of block of consecutive comments lines optionally followed by a function or variable definition.

Block of comments consists of a sequence of lines starting with exactly `#` followed by a space or tab from the beginning of the line.

Block can be separated from another block by anything else.

Comment may contain `@tag` optionally followed by whitespaces and by a value.
Each following comment will be appended to the existing `@tag` with a newline.

There are 5 types of blocks:

- Block containing `@file` describes the current file.
- Block containing `@section` starts a new section.
- Block containing `@endsection` closes current section.
- Block immediately followed by a function declaration becomes documentation for that function.
- Block immediately followed by a variable assignment becomes documentation for that function.

There is no actual difference between how the blocks are handled. You can put `@arg` tag in `@file` or put `@author` in variable description.


## @description

The main description of the item. The `@description` tag is optional. The first line of the block is used as a description.

## @file

The name of the file. Does nothing I think.

## @section

The name of the section. This is used to group functions and variables together.

Currently, only one section level is supported. I decided nesting sections is not good and renders badly.
Consecutive `@section` blocks just start a new section. `@endsection` is not needed.

## @endsection

The end of the section. This cases the section to terminate.

## @author

## @maintainer

## @option

The tag `@option` are split into code part and non-code part.

```
@option -o --longoption <var> description
```

The variable has to be `<var>`. The option have to be space separated. The `<var>` is optional. Any following text is taken as a description.

## @arg

The tag `@arg` are split into code part and non-code part.

```
@arg $1 description
@arg $@ description
@arg [$2] description
```

The tag `@arg` should be followed by `$` followed by a number or `@` or `*`. It can be optionally enclosed in square brackets. Any following text is taken as a description.

## @noargs

## @stdin

## @stdout

## @stderr

## @env

Specify used variables by the function.

## @set

Specify set variables by the function.

## @require

Specify if the item requires something, for example Bash>=5.1.

## @see

Add links. You can also link to other elements in the current file with just the name, and it will auto-replace it with an actual link.

## @exitcode or @exit

Specify if the function exits and with what and when.

## @return

Specify what function returns.

## SPDX-License-Identifier

The script parses SPDX license lines. The following lines are equivalent:

```
# SPDX-License-Identifier: GPL-3.0-or-later
# @SPDX-License-Identifier GPL-3.0-or-later
```

## shellcheck

The script also parses shellcheck lines. The following lines are equivalent:

```
# shellcheck disable=SC2086
# @shellcheck disable=SC2086
```

## @license

Specify the license.
