#!/usr/bin/env python3
import argparse
import json
import logging
import re
import textwrap
from pathlib import Path
from pprint import pprint
from typing import Any, Callable, Dict, List, Optional, Set, TextIO, Union

log = logging.getLogger(__name__)


COMMON_TAGS: Set[str] = set(
    """
    type
    name
    file
    line
    warning
    notice
    note
    """.split()
)
KNOWN_TAGS: Dict[str, Set[str]] = dict(
    file=set(
        """
        description
        author
        maintainer
        license
        SPDX-License-Identifier
        example
        data
        """.split()
    ),
    section=set(
        """
        description
        example
        data
        env
        """.split()
    ),
    function=set(
        """
        description
        option
        arg
        return
        shellcheck
        exit
        see
        example
        env
        set
        exitcode
        noargs
        stdout
        stdin
        stderr
        require
        """.split()
    ),
    variable=set(
        """
        description
        example
        see
        shellcheck
        """.split()
    ),
)

REGEX_CACHE: Dict[str, re.Pattern] = {}


def re_search(patstr: str, txt: str, opts=re.DOTALL) -> Optional[re.Match]:
    """Like re.search, but cache regexes compilation. I wonder if this is actually worth it."""
    pat = REGEX_CACHE.get(patstr)
    if not pat:
        pat = re.compile(patstr, opts)
        REGEX_CACHE[patstr] = pat
    return pat.search(txt)


def _convert_tag_arg_option(cur):
    # Convert optinos and arg into code part and description part.
    for key in ["option", "arg"]:
        for idx, elem in enumerate(cur.get(key, [])):
            # description
            mopt = re_search(
                r"""
                    ^\s*(?P<code>
                        # --longarg=var Description
                        --\S+=\S+|
                        # -l --longarg <var> Description
                        # -l --longarg [var] Description
                        --?\S+(\s+--?\S+)*(\s*(\<\S+\>|\[\S+\]))?|
                        # $1 Description
                        \$\S+|
                        # [arg] Description
                        \[\S+\]|
                        # <arg> Description
                        \<\S+\>
                    )\s*(?P<description>.*)$
                """,
                elem,
                re.VERBOSE | re.DOTALL,
            )
            if mopt:
                cur[key][idx] = dict(
                    code=mopt.group("code").strip(),
                    description=mopt.group("description") or "",
                )
            else:
                log.error(f"invalid @{key}: {repr(elem)}")
                cur[key][idx] = dict(code=" ", description=cur[key][idx])


def _convert_tag_set_env(cur):
    for key in ["set", "env"]:
        for idx, elem in enumerate(cur.get(key, [])):
            mopt = re_search(r"^\s*(\S+)\s*(.*)$", elem)
            if mopt:
                cur[key][idx] = dict(
                    code=mopt.group(1).strip(),
                    description=mopt.group(2) or "",
                )
            else:
                log.warning(f"invalid @{key}: {repr(elem)}")
                cur[key][idx] = dict(code="", description=cur[key][idx])


def _convert_see(cur, allkeys: Set[str]):
    """
    If you are a name in the @see tag, autoconvert it to a hyperlink to the name.
    allkeys - all keys in the file
    """
    for idx, elem in enumerate(cur.get("see", [])):
        m = re_search(r"^(\w+)(.*?)\s*$", elem)
        if m and m[1] in allkeys:
            # If the stuff in "see" references one of things we know about, make it an URL.
            cur["see"][idx] = f"[{m[1]}](#{m[1]}){m[2]}"
        else:
            # If "see" is an url, make it clickable automatically.
            m = re_search(r"^https?://\S+\s*$", elem)
            if m:
                cur["see"][idx] = f"[{elem}]({elem})"


def _dedent_some_tags(cur):
    """
    @option and @arg support no newlines.
    This is there to support formatting like:
    # @option -x blabla
    #            blabla
    """
    for key in ["option", "arg", "exit", "exitcode", "return", "example"]:
        for idx in range(len(cur.get(key, []))):
            if isinstance(cur[key][idx], str):
                val = cur[key][idx]
            elif isinstance(cur[key][idx], dict):
                val = cur[key][idx]["description"]
            else:
                assert False
            if "\n" in val:
                val = (
                    val.splitlines()[0].strip()
                    + "\n"
                    + textwrap.dedent("\n".join(val.splitlines()[1:]))
                )
            if isinstance(cur[key][idx], str):
                cur[key][idx] = val
            elif isinstance(cur[key][idx], dict):
                cur[key][idx]["description"] = val


def traverse(root: dict, cb: Callable[[dict], Any]):
    for i in root["data"]:
        cb(i)
        if i.get("data"):
            traverse(i, cb)


def parse_stream(
    stream: TextIO,
    file: Optional[str] = None,
    includeregex: Optional[str] = None,
    excluderegex: Optional[str] = None,
) -> dict:
    """
    Convert a shell script into a dictionary that looks like this:
    {
        type=file,
        license=somelicense,
        "SPDX-License-Identifier":"GPL=2.0",
        data=[
            {type=function,name=the_name_of_function,any_tag=[value1,value2]},
            {type=variable,name=the_name_of_the_variable,description=["some description"]},
            {type=section,name=the_section_name,
                data=[
                    nested...
                ]
            },
        ]
    }
    Technically it is a tree, as section can nest. I do not like it. There is only one section level.
    I do not particularly look at @tags.
    "data" allows to descend level below.
    Tags geven twice or more just result in more elements in the array or them.
    Each level has "type": file/section/variable/function.
    """
    root: dict = dict(type="file", file=file, data=[])
    parents: List[dict] = [root]  # Section nesting.
    cur: dict = {}  # Current element.
    cur_tag: Optional[str] = None  # Last seen @tag
    for lineno, line in enumerate(stream):
        if line and line[-1] == "\n":
            line = line[:-1]
        if line and line[-1] == "\r":
            line = line[:-1]
        # If the line does not start with #, it is the end.
        if line.startswith("#"):
            # If the line looks like a beginning of a tag.
            m = re_search(r"^#\s@([a-z]+)\s*(.*)$", line)
            if m:
                cur_tag = m[1]
                # @section and @type implies the type
                if cur_tag in ["section", "file", "endsection"]:
                    cur["type"] = cur_tag
                    # File has no newline on the end, cleanup.
                    if cur_tag == "file" and m[2].strip():
                        # Overwrite file name if not empty.
                        cur["file"] = m[2]
                        cur["line"] = lineno
                    elif cur_tag == "section":
                        # Clean up desription, it comes after.
                        cur["description"] = []
                        # Extract name of @section <this is name>
                        cur["name"] = m[2]
                        cur["file"] = file
                        cur["line"] = lineno
                    cur_tag = None
                else:
                    cur.setdefault(cur_tag, []).append(m[2] + "\n")
                continue
            # Detect shellcheck lines.
            m = re_search(r"^#\s+shellcheck\s+disable=(.*)$", line)
            if m:
                cur.setdefault("shellcheck", []).extend(
                    "SC" + x if x.isdigit() else x
                    for x in m.group(1).strip().split(",")
                )
                cur_tag = None
                continue
            # Detect SPDX lines.
            m = re_search(r"^#\s+SPDX-License-Identifier:\s+(.*)$", line)
            if m:
                cur.setdefault("SPDX-License-Identifier", []).append(m.group(1))
                cur_tag = None
                continue
            # If all stars align, append the string to the last tag element seen.
            line = re.sub(r"^#\s?(.*?)\n?$", r"\1", line)
            if cur and cur_tag is not None and len(cur.get(cur_tag, [])):
                cur[cur_tag][-1] += "\n" + line
                continue
            # Append free lines to description
            if cur.get("description"):
                cur["description"][-1] += "\n" + line
            else:
                cur["description"] = [line]
            continue
        else:
            # Line does not start with #
            # Try to detect the type depending on the next line after description.
            # I.e. is it a variable or a function?
            if (cur and "type" not in cur) or includeregex:
                regexes = [
                    # function name()
                    # function name
                    r"^function\s+(?P<function>[a-zA-Z@_]\w+).*$",
                    # name()
                    r"^(?P<function>[a-zA-Z@_]\w+)\s*[(][)].*$",
                    # : "${variable:=value}"
                    # : "${variable=value}"
                    # : ${variable:=value}
                    # : ${variable=value}
                    r'^:\s+"?\${(?P<variable>[a-zA-Z_][a-zA-Z_0-9]*):?=.*$',
                    # variable=
                    # declare variable=
                    # declare -a variable=
                    # readonly variable=
                    r"^(|readonly\s+|declare(\s+-\w+)*\s+)(?P<variable>[a-zA-Z_][a-zA-Z_0-9]*)=.*$",
                ]
                for rgx in regexes:
                    m = re_search(rgx, line)
                    if m:
                        type = (
                            "function" if m.groupdict().get("function") else "variable"
                        )
                        name = m[type]
                        _convert_tag_arg_option(cur)
                        _convert_tag_set_env(cur)
                        if cur or (includeregex and re_search(includeregex, name)):
                            cur.update(
                                dict(type=type, name=name, file=file, line=lineno)
                            )
                        break
            # If type was set, append to the result.
            if "type" in cur:
                if cur["type"] == "file":
                    # Just update the root.
                    root.update(cur)
                elif cur["type"] == "endsection":
                    # Go to parent.
                    if len(parents) > 1:
                        parents.pop()
                elif cur["type"] == "section":
                    # Descend into section.
                    cur["data"] = []
                    if len(parents) > 1:
                        parents.pop()
                    parents[-1]["data"].append(cur)
                    parents.append(cur)
                elif cur["type"] in ["function", "variable"]:
                    if not excluderegex or not re_search(excluderegex, cur["name"]):
                        # It's a function or a variable - added to current section.
                        parents[-1]["data"].append(cur)
            cur_tag = None
            cur = {}
    # Some sanity.
    assert len(parents) != 0, f"Too many @endsection: {len(parents)}"
    assert root["type"] == "file"
    assert isinstance(root["file"], str), f"top level file is not a string {root}"

    def check_node(x):
        assert isinstance(x["type"], str)
        assert isinstance(x["name"], str)
        assert x["type"] in ["function", "variable", "file", "section"]
        assert isinstance(x.get("file", ""), str)
        assert isinstance(x.get("data", []), list)

    traverse(root, check_node)
    # Create a list of all possible names.
    allnames = set()
    traverse(root, lambda x: x.get("name") and allnames.add(x["name"]))
    traverse(root, lambda x: _convert_see(x, allnames))
    traverse(root, lambda x: _dedent_some_tags(x))
    # Warn about unknown keys.
    traverse(
        root,
        lambda x: [
            log.warning(f"Unknown '@{k} {repr(v)}' in {x}")
            for k, v in x.items()
            if k not in (KNOWN_TAGS[x["type"]] | COMMON_TAGS)
        ],
    )
    return root


def parse_script(
    script: Union[Path, str],
    filename: Optional[str] = None,
    includeregex: Optional[str] = None,
    excluderegex: Optional[str] = None,
):
    with open(script) as f:
        return parse_stream(f, filename or str(script), includeregex, excluderegex)


def find_name(root, name: str, type: Optional[str] = None) -> Optional[dict]:
    obj = {}

    def findit(x):
        if x["name"] == name and (not type or x["type"] == type):
            obj["elem"] = x

    traverse(root, findit)
    return obj.get("elem")


def main():
    parser = argparse.ArgumentParser(
        description="""
            Parse documentation of a shell file and return it as a JSON
            """
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument("script", type=Path)
    parser.add_argument("name", nargs="?")
    parser.add_argument("type", nargs="?")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG)
    data = parse_script(args.script)
    if args.name:
        data = find_name(data, args.name, args.type)
    if args.json:
        print(json.dumps(data))
    else:
        pprint(data)


if __name__ == "__main__":
    main()
