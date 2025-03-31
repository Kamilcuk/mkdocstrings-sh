#!/usr/bin/env python3
import argparse
import json
import logging
import re
from pathlib import Path
from pprint import pprint
from typing import Any, Callable, Dict, List, Optional, Set, TextIO, Union

log = logging.getLogger(__name__)


COMMON_TAGS: Set[str] = set(
    """
    type
    name
    file
    lineno
    warning
    notice
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


def _convert_arg_option(cur):
    # Convert optinos and arg into code part and description part.
    for key in ["option", "arg"]:
        for idx, elem in enumerate(cur.get(key, [])):
            # -l --longarg <var> Description
            # --longarg=<var> Description
            # [$1] description
            # $1 description
            mopt = re.match(
                r"^\s*(?P<code>(--?\w+(=|\s*)(<\w+>)?\s+)+|\[?\$\S+)\s*(?P<description>.*)$",
                elem,
            )
            if not mopt:
                log.warning(f"invalid @{key}: {repr(elem)}")
                cur[key][idx] = dict(code="", description=cur[key][idx])
            else:
                cur[key][idx] = dict(
                    code=mopt.group("code").strip(),
                    description=mopt.group("description") or "",
                )


def _convert_see(cur, allkeys: Set[str]):
    for idx, elem in enumerate(cur.get("see", [])):
        m = re.match(r"^(\w+)(.*)", elem)
        if m and m[1] in allkeys:
            # If the stuff in "see" references one of things we know about, make it an URL.
            cur["see"][idx] = f"[{m[1]}](#{m[1]}){m[2]}"
        else:
            # If "see" is an url, make it clickable automatically.
            m = re.match(r"https?://\S+", elem)
            if m:
                cur["see"][idx] = f"[{elem}]({elem})"


def traverse(root: dict, cb: Callable[[dict], Any]):
    for i in root["data"]:
        cb(i)
        if i.get("data"):
            traverse(i, cb)


def parse_stream(
    stream: TextIO,
    file: Optional[str] = None,
    includeregex: Optional[str] = None,
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
        # If the line does not start with #, it is the end.
        if line.startswith("#"):
            # If the line looks like a beginning of a tag.
            m = re.search(r"^#\s@([a-z]+)\s*(.*)", line)
            if m:
                cur_tag = m[1]
                cur.setdefault(cur_tag, []).append(m[2] + "\n")
                # @section and @type implies the type
                if cur_tag in ["section", "file", "endsection"]:
                    cur["type"] = cur_tag
                    # File has no newline on the end, cleanup.
                    if cur_tag == "file" and m[2]:
                        # Overwrite file name if not empty.
                        cur["file"] = m[2]
                    if cur_tag in ["section", "endsection"]:
                        # Clean up desription, it comes after.
                        cur["description"] = []
                        # Don't keep @section or @endsection around.
                        del cur[cur_tag]
                        # Extract name of @section <this is name>
                        cur["name"] = m[2]
                    cur_tag = None
                continue
            # Detect shellcheck lines.
            m = re.search(r"^#\s+shellcheck\s+disable=(.*)", line)
            if m:
                cur.setdefault("shellcheck", []).extend(
                    "SC" + x if x.isdigit() else x
                    for x in m.group(1).strip().split(",")
                )
                cur_tag = None
                continue
            # Detect SPDX lines.
            m = re.search(r"#\s+SPDX-License-Identifier:\s+(.*)", line)
            if m:
                cur.setdefault("SPDX-License-Identifier", []).append(m.group(1))
                cur_tag = None
                continue
            # If all stars align, append the string to the last tag element seen.
            line = re.sub(r"#\s?", "", line)
            if cur and cur_tag is not None and len(cur.get(cur_tag, [])):
                cur[cur_tag][-1] += line
                continue
            # Append free lines to description.
            cur.setdefault("description", []).insert(
                0, (cur["description"][0] if cur.get("description") else "") + line
            )
            continue
        else:
            # Line does not start with #
            # Try to detect the type depending on the next line after description.
            # I.e. is it a variable or a function?
            if (cur and "type" not in cur) or includeregex:
                regexes = [
                    # function name()
                    # function name
                    r"^function\s+(?P<function>[a-zA-Z@_]\w+)",
                    # name()
                    r"^(?P<function>[a-zA-Z@_]\w+)\s*[(][)]",
                    # : "${variable:=value}"
                    # : "${variable=value}"
                    # : ${variable:=value}
                    # : ${variable=value}
                    r'^:\s+"?\${(?P<variable>[a-zA-Z_][a-zA-Z_0-9]*):?=',
                    # variable=
                    # declare variable=
                    # declare -a variable=
                    # readonly variable=
                    r"^(|readonly\s+|declare(\s+-\w+)*\s+)(?P<variable>[a-zA-Z_][a-zA-Z_0-9]*)=",
                ]
                for rgx in regexes:
                    m = re.search(rgx, line)
                    if m:
                        type = (
                            "function" if m.groupdict().get("function") else "variable"
                        )
                        name = m[type]
                        _convert_arg_option(cur)
                        if cur or (includeregex and re.search(includeregex, name)):
                            cur.update(dict(type=type, name=name))
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
                    # It's a function or a variable - added to current section.
                    parents[-1]["data"].append(cur)
            cur_tag = None
            cur = {}
    # Some sanity.
    assert len(parents) != 0, f"Too many @endsection: {len(parents)}"
    assert root["type"] == "file"

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


def parse_script(script: Union[Path, str]):
    with open(script) as f:
        return parse_stream(f, str(script))


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
