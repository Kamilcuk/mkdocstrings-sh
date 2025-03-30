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
- Block immidately followed by a function declaration becomes documentation for that function.
- Block immidately followed by a variable assignment becomes documentation for that function.

There is no actual difference between how the blocks are handled.

Currently, only one section level is supported. I decided nesting sections is not good and renders badly.
Consecutive `@section` blocks just start a new section. `@endsection` is not needed.

Additionally lines in the form of shellcheck and SPDX-License-Identifier are detected and handled as-if they are `@shellcheck` or `@SPDX-License-Identifier`.

## @arg and @option

The tags `@arg` and `@option` are split into code part and non-code part.

