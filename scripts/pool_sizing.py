#!/usr/bin/env python3
"""Check a deployment's PostgreSQL connection ceiling against the server's limits.

Every replica opens its own pool against the one primary, so the ceiling is a
property of the deployment: the most gateway pods that can run at once
(autoscaler maximum and rollout surge included) times DATABASE_POOL_MAX, plus
every other client named as headroom, must fit in max_connections less the
slots PostgreSQL reserves. An over-committed deployment is rejected with the
arithmetic and the largest settings that would fit. Nothing is ever changed.
See docs/deployment/pool-sizing.md.
"""
import argparse
import base64
import binascii
import json
from pathlib import Path
import re
import shlex
import sys

ROOT = Path(__file__).resolve().parents[1]
MAX_INPUT_BYTES = 4 * 1024 * 1024
# gateway/src/config.rs: DEFAULT_DATABASE_POOL_MAX and MAX_DATABASE_POOL_MAX.
DEFAULT_POOL_MAX = 10
MAX_POOL_MAX = 256
# PostgreSQL's MAX_BACKENDS, the largest max_connections the server accepts.
MAX_CONNECTIONS_LIMIT = 262143
SERVER_SETTINGS = ("max_connections", "superuser_reserved_connections", "reserved_connections")
POSTGRES_DEFAULTS = {"max_connections": 100, "superuser_reserved_connections": 3, "reserved_connections": 0}
SIZING_ENV = ("STATE_BACKEND", "DATABASE_POOL_MAX")
GATEWAY_BINARIES = ("/usr/local/bin/gateway", "gateway")
POOLER_MODES = ("none", "session", "transaction", "statement")

# Every connection consumer beside the serving pools, in report order: name,
# default (None when only the operator can know it) and what it covers.
HEADROOM = (
    ("migrator", 2, "`gateway migrate up`: the migrator and its advisory-lock session"),
    ("import", 2, "`gateway import-standalone`, during a cutover"),
    ("maintenance", 4, "one `maintenance-run` (up to 3) and one other one-shot command (1) at once"),
    ("backup", None, "backup tooling: `pg_dump` opens 1, `pg_dump --jobs=N` opens N+1"),
    ("monitoring", None, "database exporters and monitoring queries"),
    ("operator", None, "operator `psql` sessions"),
    ("other", None, "every other client of this server"),
)
HEADROOM_NAMES = tuple(name for name, _, _ in HEADROOM)

# One-shot cluster commands: the headroom entry each is budgeted under and how
# many connections one run can hold open at once.
COMMANDS = {
    "migrate": ("migrator", 2),
    "import-standalone": ("import", 2),
    "maintenance-run": ("maintenance", 3),
    "cluster-members": ("maintenance", 1),
    "revoke-jwt": ("maintenance", 1),
    "jwt-revocations-cleanup": ("maintenance", 1),
    "rate-limit-buckets-cleanup": ("maintenance", 1),
}

# What the shipped cluster-mode examples budget beyond their gateway pools.
# `uncounted` is the reviewed list of services that open no gateway pool, so a
# client added to an example is rejected until its connections are budgeted.
# Each names the server its gateways use: `server_service`, a PostgreSQL
# service in the file, or `server`, that server's three limits.
EXAMPLE_BUDGETS = {
    "docs/deployment/docker-compose.ha.yml": {
        "pooler": "none",
        "headroom": {"backup": 1, "monitoring": 1, "operator": 2, "other": 0},
        "uncounted": ["db-bootstrap", "db-grants", "lb"],
        # The example's own PostgreSQL container is the server its gateways'
        # DSN files name.
        "server_service": "db",
    },
}
KUSTOMIZATION_KEYS = {"apiVersion", "kind", "resources", "patches", "namespace", "commonLabels",
                      "labels", "commonAnnotations", "images"}
# Fields a Kustomize patch may not touch, because they move a sizing input.
PATCH_SIZING_FIELDS = {"replicas", "strategy", "updateStrategy", "envFrom", "command", "args",
                       "parallelism", "concurrencyPolicy", "jobTemplate", "scaleTargetRef",
                       "maxReplicas", "minReplicas", "maxReplicaCount"}
POD_TEMPLATES = {
    "Deployment": ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"),
    "ReplicaSet": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
    "Pod": ("spec",),
}
# The files Compose reads when it is run without -f, and the override file it
# then merges over them.
COMPOSE_DEFAULT_FILES = ("compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml")
COMPOSE_OVERRIDE_FILES = ("compose.override.yml", "compose.override.yaml", "docker-compose.override.yml",
                          "docker-compose.override.yaml")
POSTGRES_IMAGE = re.compile(
    r"(?:(?:docker\.io|index\.docker\.io|registry-1\.docker\.io)/)?(?:library/)?postgres(?:[:@].*)?")


class InputError(ValueError):
    """The input cannot be read with certainty, so nothing was decided."""


class Unresolved:
    """An environment value the files read do not determine."""

    def __init__(self, reason):
        self.reason = reason


# ---------------------------------------------------------------------------
# A conservative reader for the block-style YAML that deployment files use.

# Characters YAML tools disagree about. Compose, kubectl and PyYAML break lines
# on a lone carriage return, NEL, LINE SEPARATOR and PARAGRAPH SEPARATOR, where
# this reader would not, and YAML refuses the remaining control characters. A
# byte-order mark may only open the file. Refusing all of them keeps the guard
# from reading a document other than the one the deployment tool reads.
AMBIGUOUS_CHARACTER = re.compile(
    "[^\t\n\r\x20-\x7e\xa0-\u2027\u202a-\ud7ff\ue000-\ufefe\uff00-\ufffd\U00010000-\U0010ffff]|\r(?!\n)")
# How many nodes a document may expand to once its aliases are followed, so a
# small file of nested aliases cannot make every later walk take for ever.
MAX_EXPANDED_NODES = 1_000_000
NULLS = ("~", "null", "Null", "NULL")


def refuse_ambiguous_characters(text, source):
    match = AMBIGUOUS_CHARACTER.search(text)
    if match is None:
        return
    line = text.count("\n", 0, match.start()) + 1
    char = match.group(0)
    what = ("a carriage return that does not end a CRLF line break" if char == "\r"
            else f"the character U+{ord(char):04X}")
    raise InputError(f"{source}:{line}: contains {what}, which YAML tools read as a line break or refuse; "
                     "the guard refuses it rather than read the file differently from them")


def expanded_size(node, where, sizes=None):
    """How many nodes `node` holds, a shared (aliased) node counted each time it appears."""
    sizes = {} if sizes is None else sizes
    if not isinstance(node, (dict, list)):
        return 1
    if id(node) in sizes:
        return sizes[id(node)]
    total = 1
    for child in node.values() if isinstance(node, dict) else node:
        total += expanded_size(child, where, sizes)
        if total > MAX_EXPANDED_NODES:
            raise InputError(f"{where}: expands to more than {MAX_EXPANDED_NODES} nodes once its aliases are "
                             "followed")
    sizes[id(node)] = total
    return total


class _Yaml:
    """Block mappings and sequences, single-line plain and quoted scalars,
    literal and folded block scalars, single-line flow collections of scalars,
    anchors, aliases, merge keys and comments. Anything else it knows of
    (tags, directives, complex keys, multi-line plain, quoted or flow scalars,
    characters YAML tools disagree about, flow scalars that YAML tools split
    differently) is refused: a misread pool size is worse than none. It is
    not a full YAML parser, so CI also compares its reading of the HA example
    with Compose's own rendering.
    """

    def __init__(self, text, source):
        self.source = source
        refuse_ambiguous_characters(text, source)
        self.lines = text.replace("\r\n", "\n").split("\n")
        if self.lines[-1] == "":
            # The last line break ends a line; it does not start another.
            self.lines.pop()
        self.index = 0
        self.virtual = {}
        self.anchors = {}

    def fail(self, message, index=None):
        line = (self.index if index is None else index) + 1
        raise InputError(f"{self.source}:{line}: {message}")

    def documents(self):
        documents = []
        while True:
            while self.index < len(self.lines) and not self.marker(self.index) and self.blank(self.index):
                self.index += 1
            if self.index >= len(self.lines):
                return documents
            raw = self.lines[self.index]
            if raw.startswith("%"):
                self.fail("YAML directives are not supported")
            if self.marker(self.index):
                rest = raw[3:].strip()
                if rest and not rest.startswith("#"):
                    self.fail("content on a document marker line is not supported")
                self.index += 1
                continue
            self.anchors = {}
            start = self.index
            node = self.node(0)
            if self.peek() is not None:
                self.fail("unexpected content after the document")
            expanded_size(node, f"{self.source}:{start + 1}: the document")
            if node is not None:
                documents.append(node)

    def marker(self, index):
        raw = self.lines[index]
        return index not in self.virtual and raw[:3] in ("---", "...") and raw[3:4] in ("", " ", "\t")

    def blank(self, index):
        if index in self.virtual:
            return False
        stripped = self.lines[index].strip(" \t")
        return stripped == "" or stripped.startswith("#")

    def line(self, index):
        if index in self.virtual:
            return self.virtual[index]
        raw = self.lines[index]
        content = raw.lstrip(" ")
        if content.startswith("\t"):
            self.fail("tabs cannot indent YAML", index)
        return len(raw) - len(content), content.rstrip(" \t")

    def peek(self):
        while self.index < len(self.lines):
            if self.marker(self.index):
                return None
            if not self.blank(self.index):
                return self.line(self.index)
            self.index += 1
        return None

    def node(self, minimum):
        head = self.peek()
        if head is None or head[0] < minimum:
            return None
        indent, content = head
        if self.sequence_entry(content):
            return self.sequence(indent)
        if self.split_key(content) is not None:
            return self.mapping(indent)
        # A node on a line of its own belongs to the collection above it, so a
        # block scalar here may indent its content less than its header.
        return self.value(content, indent, "node", minimum - 1)

    @staticmethod
    def sequence_entry(content):
        return content == "-" or content.startswith(("- ", "-\t"))

    def mapping(self, indent):
        explicit, merges = {}, []
        while True:
            head = self.peek()
            if head is None or head[0] < indent:
                break
            if head[0] > indent:
                self.fail("unexpected indentation")
            if self.sequence_entry(head[1]):
                break
            split = self.split_key(head[1])
            if split is None:
                self.fail("expected a mapping entry")
            key, rest, quoted = split
            if not quoted and key in NULLS:
                self.fail("a null mapping key is not supported")
            start = self.index
            value = self.value(rest, indent, "map")
            if key == "<<" and not quoted:
                sources = value if isinstance(value, list) else [value]
                if not sources or not all(isinstance(source, dict) for source in sources):
                    self.fail("a merge key needs a mapping or a list of mappings", start)
                merges.extend(sources)
            elif key in explicit:
                self.fail(f"duplicate key {key!r}", start)
            else:
                explicit[key] = value
        result = {}
        for source in merges:
            for key, value in source.items():
                result.setdefault(key, value)
        result.update(explicit)
        return result

    def sequence(self, indent):
        items = []
        while True:
            head = self.peek()
            if head is None or head[0] < indent:
                break
            if head[0] > indent:
                self.fail("unexpected indentation")
            if not self.sequence_entry(head[1]):
                break
            rest = head[1][1:]
            if "\t" in rest[:len(rest) - len(rest.lstrip(" \t"))]:
                self.fail("a tab cannot follow a sequence entry's dash")
            stripped = rest.lstrip(" ")
            if stripped == "" or stripped.startswith("#"):
                self.index += 1
                items.append(self.nested(indent, "seq"))
            elif self.sequence_entry(stripped) or self.split_key(stripped) is not None:
                # A compact nested collection: read this line again with the
                # dash counted as indentation.
                offset = indent + 1 + len(rest) - len(stripped)
                self.virtual[self.index] = (offset, stripped)
                items.append(self.node(offset))
            else:
                items.append(self.value(stripped, indent, "seq"))
        return items

    def nested(self, indent, context):
        head = self.peek()
        if head is None:
            return None
        if head[0] > indent:
            return self.node(indent + 1)
        if context == "map" and head[0] == indent and self.sequence_entry(head[1]):
            return self.sequence(indent)
        return None

    def split_key(self, content):
        """(key, rest, quoted) when content opens a mapping entry, else None."""
        if content[:1] in ("'", '"'):
            try:
                key, end = self.quoted(content, 0)
            except InputError:
                return None
            after = content[end:].lstrip(" ")
            if after[:1] == ":" and after[1:2] in ("", " ", "\t"):
                return key, after[1:].strip(" \t"), True
            return None
        if content[:1] in tuple("[]{},#&*!|>%@`") or self.sequence_entry(content) \
                or (content[:1] == "?" and content[1:2] in ("", " ", "\t")):
            return None
        comment = re.search(r"[ \t]#", content)
        match = re.search(r":(?=[ \t]|$)", content[:comment.start()] if comment else content)
        if match is None or not content[:match.start()].strip(" \t"):
            return None
        return content[:match.start()].rstrip(" \t"), content[match.end():].strip(" \t"), False

    def value(self, text, indent, context, parent=None):
        """The node a line's text starts, leaving the index after it.

        `parent` is the indentation a block scalar's content must exceed,
        when that is not the line's own.
        """
        if text == "" or text.startswith("#"):
            self.index += 1
            return self.nested(indent, context)
        if text[0] in "&*":
            match = re.match(r"([&*])([^\s\[\]{},]+)", text)
            if not match:
                self.fail("an anchor or alias needs a name")
            rest = text[match.end():].lstrip(" \t")
            name = match.group(2)
            if match.group(1) == "*":
                if rest and not rest.startswith("#"):
                    self.fail("an alias stands alone")
                if name not in self.anchors:
                    self.fail(f"unknown alias *{name}")
                self.end_of_value(indent)
                return self.anchors[name]
            if rest[:1] in ("&", "*"):
                self.fail("an anchored node cannot be an alias or carry two anchors")
            node = self.value(rest, indent, context, parent)
            self.anchors[name] = node
            return node
        if text[0] == "!":
            self.fail("YAML tags are not supported")
        if text[0] in "%@`":
            self.fail(f"reserved indicator {text[0]!r}")
        if text[:1] == "?" and text[1:2] in ("", " ", "\t"):
            self.fail("complex mapping keys are not supported")
        if text[0] in "|>":
            return self.block_scalar(text, indent if parent is None else parent)
        if text[0] in "[{":
            node, end = self.flow(text, 0)
            self.trailing(text[end:])
            self.end_of_value(indent)
            return node
        if text[0] in "'\"":
            node, end = self.quoted(text, 0)
            self.trailing(text[end:])
            self.end_of_value(indent)
            return node
        if context == "map" and self.sequence_entry(text):
            self.fail("a sequence cannot start on its key's line")
        comment = re.search(r"[ \t]#", text)
        plain = (text[:comment.start()] if comment else text).rstrip(" \t")
        if re.search(r":([ \t]|$)", plain):
            self.fail("a plain scalar cannot contain ': '; quote it")
        self.end_of_value(indent)
        return None if plain in NULLS else plain

    def trailing(self, rest):
        rest = rest.strip(" \t")
        if rest and not rest.startswith("#"):
            self.fail("unexpected text after a value")

    def end_of_value(self, indent):
        self.index += 1
        head = self.peek()
        if head is not None and head[0] > indent:
            self.fail("a value cannot continue on a more indented line; multi-line scalars must be block scalars")

    def quoted(self, text, start):
        quote, index, out = text[start], start + 1, []
        escapes = {"0": "\0", "a": "\a", "b": "\b", "t": "\t", "\t": "\t", "n": "\n", "v": "\v",
                   "f": "\f", "r": "\r", "e": "\x1b", " ": " ", '"': '"', "/": "/", "\\": "\\",
                   "N": "\x85", "_": "\xa0", "L": "\u2028", "P": "\u2029"}
        while index < len(text):
            char = text[index]
            if quote == "'" and char == "'":
                if text[index + 1:index + 2] == "'":
                    out.append("'")
                    index += 2
                    continue
                return "".join(out), index + 1
            if quote == '"' and char == '"':
                return "".join(out), index + 1
            if quote == '"' and char == "\\":
                code = text[index + 1:index + 2]
                widths = {"x": 2, "u": 4, "U": 8}
                if code in widths:
                    digits = text[index + 2:index + 2 + widths[code]]
                    if not re.fullmatch(r"[0-9A-Fa-f]{%d}" % widths[code], digits):
                        self.fail("invalid escape in a double-quoted scalar")
                    out.append(chr(int(digits, 16)))
                    index += 2 + widths[code]
                    continue
                if code not in escapes:
                    self.fail("invalid escape in a double-quoted scalar")
                out.append(escapes[code])
                index += 2
                continue
            out.append(char)
            index += 1
        self.fail("a quoted scalar must close on its own line")

    def flow(self, text, start):
        closer = "]" if text[start] == "[" else "}"
        result = [] if closer == "]" else {}
        index = start + 1
        while True:
            index = self.skip_spaces(text, index)
            if index >= len(text):
                self.fail("a flow collection must close on its own line")
            if text[index] == closer:
                return result, index + 1
            plain = text[index] not in "'\""
            item, index = self.flow_scalar(text, index, closer, closer == "}")
            if closer == "}":
                if plain and item is None:
                    self.fail("a null mapping key is not supported")
                index = self.skip_spaces(text, index)
                if text[index:index + 1] != ":":
                    self.fail("expected ':' in a flow mapping")
                value, index = self.flow_scalar(text, self.skip_spaces(text, index + 1), closer, False)
                if item in result:
                    self.fail(f"duplicate key {item!r}")
                result[item] = value
            else:
                result.append(item)
            index = self.skip_spaces(text, index)
            if text[index:index + 1] == ",":
                index += 1
            elif text[index:index + 1] != closer:
                self.fail("expected ',' or the end of the flow collection")

    def flow_scalar(self, text, index, closer, key):
        """A flow entry's scalar. A plain one ends at a flow indicator, or as a
        key at a ':' that a space, a tab or the end of the line follows; any
        other ':' belongs to the scalar, as YAML has it. Where YAML tools split
        a plain flow scalar differently from each other (a '?', a ':' beside a
        space or a flow indicator) it is refused."""
        if index >= len(text):
            self.fail("a flow collection must close on its own line")
        char, after = text[index], text[index + 1:index + 2]
        if char in "[{":
            self.fail("nested flow collections are not supported")
        if char in "&*!|>%@`#?:" or (char == "-" and after in ("", " ", "\t", ",", "]", "}")):
            self.fail(f"unsupported indicator {char!r} in a flow collection")
        if char in "'\"":
            return self.quoted(text, index)
        end = index
        while end < len(text) and text[end] not in ",[]{}":
            char, after = text[end], text[end + 1:end + 2]
            if char == "?":
                self.fail("YAML tools split a plain flow scalar at a '?' differently; quote the scalar")
            if char == ":":
                if after in ("", " ", "\t"):
                    if key:
                        break
                    self.fail("a flow scalar cannot contain ': '; quote it")
                if after in ",[]{}" or text[end - 1] in " \t":
                    self.fail("YAML tools read a ':' beside a space or a flow indicator differently; quote the "
                              "scalar or put one space after the ':'")
            end += 1
        plain = text[index:end].strip(" \t")
        if re.search(r"[ \t]#", plain):
            self.fail("a comment cannot sit inside a flow collection")
        if plain == "" and (key or closer == "]"):
            self.fail("an empty entry in a flow collection is not supported")
        return (None if plain == "" or plain in NULLS else plain), end

    @staticmethod
    def skip_spaces(text, index):
        while index < len(text) and text[index] in " \t":
            index += 1
        return index

    def block_scalar(self, header, parent):
        match = re.fullmatch(r"([|>])([+-]?)(?:[ \t]+#.*)?", header)
        if not match:
            self.fail("unsupported block scalar header; indentation indicators are not supported")
        style, chomp = match.groups()
        start = index = self.index + 1
        width = None
        while index < len(self.lines):
            raw = self.lines[index]
            if raw.strip(" ") == "":
                index += 1
                continue
            indent = len(raw) - len(raw.lstrip(" "))
            if width is None:
                if indent <= parent:
                    break
                width = indent
            elif indent < width:
                break
            if "\t" in raw[:width]:
                self.fail("tabs cannot indent YAML", index)
            index += 1
        if width is None:
            lines = [""] * (index - start)
        else:
            # Spaces past the content's indentation are content, even on a
            # line that holds nothing else; before the first line YAML
            # refuses them.
            lines = [raw[width:] for raw in self.lines[start:index]]
            leading = next(number for number, line in enumerate(lines) if line.strip(" "))
            if any(lines[:leading]):
                self.fail("a block scalar's leading blank line is indented more than its first line", start)
        trailing = 0
        while lines and lines[-1] == "":
            lines.pop()
            trailing += 1
        if style == "|":
            text = "\n".join(lines)
        else:
            text, previous, breaks = "", None, 0
            for line in lines:
                if line == "":
                    breaks += 1
                    continue
                kind = "more" if line[0] in " \t" else "normal"
                if previous is None:
                    text = "\n" * breaks + line
                elif previous == kind == "normal":
                    text += (" " if breaks == 0 else "\n" * breaks) + line
                else:
                    text += "\n" * (breaks + 1) + line
                previous, breaks = kind, 0
        self.index = index
        if chomp == "-" or not lines:
            return text if lines else ("\n" * trailing if chomp == "+" else "")
        return text + "\n" + ("\n" * trailing if chomp == "+" else "")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_documents(path, source):
    """Every document in a YAML file, or the one value of a JSON file."""
    try:
        with open(path, "rb") as stream:
            data = stream.read(MAX_INPUT_BYTES + 1)
    except OSError as error:
        raise InputError(f"{source}: cannot be read: {error.strerror}") from error
    if len(data) > MAX_INPUT_BYTES:
        raise InputError(f"{source}: exceeds the {MAX_INPUT_BYTES}-byte input limit")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise InputError(f"{source}: is not UTF-8") from error
    refuse_ambiguous_characters(text, source)
    if text.lstrip(" \t\r\n")[:1] in ("{", "["):
        try:
            return [json.loads(text, object_pairs_hook=_unique_pairs)]
        except json.JSONDecodeError as error:
            raise InputError(f"{source}:{error.lineno}: invalid JSON: {error.msg}") from error
        except InputError as error:
            raise InputError(f"{source}: {error}") from error
        except RecursionError as error:
            raise InputError(f"{source}: nests too deeply to read") from error
    try:
        return _Yaml(text, source).documents()
    except RecursionError as error:
        raise InputError(f"{source}: nests too deeply to read") from error


# ---------------------------------------------------------------------------
# Values shared by every reader.


def count(value, where, minimum=0, maximum=None):
    """A whole number written plainly: no sign, exponent, separator or base."""
    if isinstance(value, int) and not isinstance(value, bool):
        number = value
    elif isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]*", value):
        number = int(value)
    else:
        raise InputError(f"{where} must be a whole number, got {value!r}")
    if number < minimum or (maximum is not None and number > maximum):
        bound = f"between {minimum} and {maximum}" if maximum is not None else f"at least {minimum}"
        raise InputError(f"{where} must be {bound}, got {number}")
    return number


def backend_of(env, where):
    """Which state backend a gateway process with this environment selects."""
    if "STATE_BACKEND" not in env:
        return "sqlite"
    value = env["STATE_BACKEND"]
    if isinstance(value, Unresolved):
        raise InputError(f"{where}: STATE_BACKEND {value.reason}")
    if not isinstance(value, str) or value.strip() not in ("sqlite", "postgres"):
        raise InputError(f"{where}: STATE_BACKEND must be sqlite or postgres, got {value!r}; "
                         "the gateway refuses to start")
    return value.strip()


def pool_max_of(env, where):
    """(DATABASE_POOL_MAX, where it came from), validated as the gateway does."""
    if "DATABASE_POOL_MAX" not in env:
        return DEFAULT_POOL_MAX, "gateway default"
    value = env["DATABASE_POOL_MAX"]
    if isinstance(value, Unresolved):
        raise InputError(f"{where}: DATABASE_POOL_MAX {value.reason}")
    if isinstance(value, int) and not isinstance(value, bool):
        value = str(value)
    if isinstance(value, str) and re.fullmatch(r"0[0-9]+", value):
        # The gateway reads 010 as ten, but Compose's YAML reads it as octal.
        raise InputError(f"{where}: DATABASE_POOL_MAX {value!r} has a leading zero, which YAML tools read as "
                         "octal; write it without one")
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+", value) or not 1 <= int(value) <= MAX_POOL_MAX:
        raise InputError(f"{where}: DATABASE_POOL_MAX must be a whole number between 1 and {MAX_POOL_MAX}, "
                         f"got {value!r}; the gateway refuses to start")
    return int(value), "DATABASE_POOL_MAX"


def command_of(argv, where):
    """The one-shot command a cluster-mode gateway process runs."""
    if argv[0] not in COMMANDS:
        raise InputError(f"{where} runs `{argv[0]}` with STATE_BACKEND=postgres, and the guard does not know "
                         "how many connections that command opens")
    return argv[0]


def string_list(value, where):
    if isinstance(value, str):
        try:
            return shlex.split(value)
        except ValueError as error:
            raise InputError(f"{where} cannot be split into arguments: {error}") from error
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise InputError(f"{where} must be a list of strings")
    return list(value)


def mapping(value, where, default=None):
    if value is None:
        return {} if default is None else default
    if not isinstance(value, dict):
        raise InputError(f"{where} must be a mapping")
    return value


def items_of(value, where):
    if value is None:
        return []
    if not isinstance(value, list):
        raise InputError(f"{where} must be a list")
    return value


# ---------------------------------------------------------------------------
# Compose.


def compose_environment(value, where):
    pairs = []
    if isinstance(value, dict):
        pairs = list(value.items())
    elif isinstance(value, list):
        for entry in value:
            if not isinstance(entry, str):
                raise InputError(f"{where}: environment entries must be strings")
            name, separator, text = entry.partition("=")
            pairs.append((name, text if separator else None))
    elif value is not None:
        raise InputError(f"{where}: environment must be a mapping or a list")
    env = {}
    for name, text in pairs:
        if name in SIZING_ENV:
            if name in env:
                raise InputError(f"{where}: {name} is set twice")
            if text is None:
                text = Unresolved("takes its value from the shell that runs Compose; render the file with "
                                  "`docker compose config --format json` and check the rendered output")
            elif isinstance(text, str) and "$" in text:
                text = Unresolved("is interpolated by Compose; render the file with "
                                  "`docker compose config --format json` and check the rendered output")
        env[name] = text
    return env


def compose_argv(service, where):
    args = string_list(service["command"], f"{where} command") if service.get("command") is not None else []
    if service.get("entrypoint") is not None:
        entrypoint = string_list(service["entrypoint"], f"{where} entrypoint")
        if not entrypoint or entrypoint[0] not in GATEWAY_BINARIES:
            raise InputError(f"{where} replaces the gateway's entrypoint, so the guard cannot tell what it runs")
        args = entrypoint[1:] + args
    return args


def compose_replicas(service, where):
    deploy = mapping(service.get("deploy"), f"{where} deploy")
    if deploy.get("mode") not in (None, "replicated"):
        raise InputError(f"{where} uses deploy.mode {deploy.get('mode')!r}; only a replicated service has a "
                         "replica count the guard can read")
    counts = []
    if service.get("scale") is not None:
        counts.append(count(service["scale"], f"{where} scale"))
    if deploy.get("replicas") is not None:
        counts.append(count(deploy["replicas"], f"{where} deploy.replicas"))
    if len(set(counts)) > 1:
        raise InputError(f"{where} sets scale and deploy.replicas to different values")
    replicas = counts[0] if counts else 1
    update = mapping(deploy.get("update_config"), f"{where} deploy.update_config")
    surge = 0
    if update.get("order") == "start-first":
        parallelism = count(update.get("parallelism", 1), f"{where} deploy.update_config.parallelism")
        surge = replicas if parallelism == 0 else min(parallelism, replicas)
    return replicas, surge


def server_settings(args, where):
    """The connection settings a postgres command line passes."""
    settings, index = {}, 0
    while index < len(args):
        arg, name = args[index], None
        if arg in ("-c", "-N") and index + 1 < len(args):
            index += 1
            name, text = ("max_connections", args[index]) if arg == "-N" else args[index].partition("=")[::2]
        elif arg.startswith("-c") and len(arg) > 2:
            name, text = arg[2:].partition("=")[::2]
        elif arg.startswith("-N") and len(arg) > 2:
            name, text = "max_connections", arg[2:]
        elif arg.startswith("--") and "=" in arg:
            name, text = arg[2:].partition("=")[::2]
        index += 1
        if name is None:
            continue
        name = name.strip().lower().replace("-", "_")
        if name == "config_file":
            raise InputError(f"{where} reads its settings from a file the guard cannot see; pass the server's "
                             "limits explicitly")
        if name in SERVER_SETTINGS:
            number = count(text.strip(), f"{where} {name}")
            if settings.get(name, number) != number:
                raise InputError(f"{where} sets {name} twice")
            settings[name] = number
    return settings


def compose_server(service, where):
    """The arguments a PostgreSQL server service passes the server, or None for any other service."""
    argv = string_list(service["command"], f"{where} command") if service.get("command") is not None else []
    image = service.get("image")
    postgres_image = isinstance(image, str) and POSTGRES_IMAGE.fullmatch(image) is not None
    if argv[:1] == ["postgres"]:
        return argv[1:]
    if postgres_image and service.get("entrypoint") is None and (not argv or argv[0].startswith("-")):
        return argv
    return None


def compose_server_limits(name, args, where):
    """A confirmed server service's limits: its command line, else PostgreSQL's defaults."""
    settings = server_settings(args, where)
    return {key: (settings[key], f"service {name} command") if key in settings
            else (POSTGRES_DEFAULTS[key], "PostgreSQL default; not on the service's command line")
            for key in SERVER_SETTINGS}


def refuse_compose_overrides(path):
    """Refuse a file Compose would read with an override file merged over it."""
    path = Path(path)
    if path.name.lower() not in COMPOSE_DEFAULT_FILES:
        return
    for name in COMPOSE_OVERRIDE_FILES:
        if (path.parent / name).is_file():
            raise InputError(f"{path}: Compose merges {name} over this file when it runs without -f; render the "
                             "two with `docker compose config --format json` and check the rendered output")


def compose_facts(document, source):
    """Gateway pools, one-shot jobs, uncounted services and PostgreSQL servers in a Compose file.

    A PostgreSQL service is only a candidate: the gateways' DSN is a secret
    file, so which server they use is the operator's to confirm.
    """
    services = document.get("services") if isinstance(document, dict) else None
    if not isinstance(services, dict) or not services:
        raise InputError(f"{source}: a Compose file needs a non-empty services mapping")
    if document.get("include") is not None:
        raise InputError(f"{source} includes other Compose files; render it with `docker compose config --format json` "
                         "and check the rendered output")
    facts = {"pools": [], "jobs": [], "uncounted": [], "servers": {}}
    for name, service in services.items():
        where = f"{source}: service {name}"
        if not isinstance(service, dict):
            raise InputError(f"{where} must be a mapping")
        for key in ("extends", "env_file"):
            if service.get(key) is not None:
                raise InputError(f"{where} uses {key}; render the file with `docker compose config --format json` "
                                 "and check the rendered output")
        server_args = compose_server(service, where)
        if server_args is not None:
            facts["servers"][name] = server_args
            continue
        env = compose_environment(service.get("environment"), where)
        if backend_of(env, where) != "postgres":
            facts["uncounted"].append(name)
            continue
        argv = compose_argv(service, where)
        replicas, surge = compose_replicas(service, where)
        if argv:
            command = command_of(argv, where)
            facts["jobs"].append({"name": f"service {name}", "command": command, "instances": max(replicas, 1)})
            continue
        pool_max, origin = pool_max_of(env, where)
        facts["pools"].append({"name": f"service {name}", "replicas": replicas, "autoscaler_max": None,
                               "surge": surge, "pool_max": pool_max, "pool_origin": origin})
    return facts


def select_server(facts, source, server_service, declared, origin):
    """(limits, confirmed service or None, PostgreSQL services ignored).

    `declared` maps the three settings to numbers, or is None. The operator
    either names the service in the file that is the gateways' server, or
    declares the server's limits, in which case every PostgreSQL service in
    the file is reported as ignored. Without either, a file that runs
    PostgreSQL is refused rather than assumed to be the gateways' server.
    """
    servers = facts.get("servers", {})
    if server_service is not None and declared is not None:
        raise InputError(f"{source}: name either the server service or the server's limits, not both")
    if server_service is not None:
        if server_service not in servers:
            found = f" (the file runs PostgreSQL as {', '.join(servers)})" if servers else ""
            raise InputError(f"{source}: service {server_service} is named as the gateways' PostgreSQL server, but it "
                             "is not a PostgreSQL service the guard recognises, one that runs the official postgres "
                             f"image or a command that starts with postgres{found}; name the server's limits instead")
        limits = compose_server_limits(server_service, servers[server_service],
                                       f"{source}: service {server_service}")
        return limits, server_service, [name for name in servers if name != server_service]
    if declared is not None:
        return {key: (value, origin) for key, value in declared.items()}, None, list(servers)
    if servers:
        names = ", ".join(servers)
        raise InputError(f"{source} runs PostgreSQL ({names}), and its gateways' DSN is a secret file, so the guard "
                         f"cannot tell whether they use it; confirm the server with --server-service NAME, or name "
                         "the server the gateways use with --max-connections, --superuser-reserved-connections and "
                         "--reserved-connections")
    raise InputError("name the server's limits with --max-connections, --superuser-reserved-connections "
                     "and --reserved-connections (0 before PostgreSQL 16); check them with SHOW")


# ---------------------------------------------------------------------------
# Kubernetes.


def kubernetes_objects(documents):
    """(source, object) for every object, lists expanded.

    kubectl reads any object with an `items` field as a list, whatever its
    kind (a `List`, a `DeploymentList`), and flattens lists inside lists.
    """
    pending = list(reversed(documents))
    while pending:
        source, document = pending.pop()
        if isinstance(document, dict) and "items" in document:
            items = items_of(document["items"], f"{source}: {document.get('kind')} items")
            pending.extend((source, item) for item in reversed(items))
        else:
            yield source, document


def secret_values(secret, where):
    values = {}
    for key, value in mapping(secret.get("data"), f"{where} data").items():
        try:
            if not isinstance(value, str):
                raise ValueError("not a string")
            values[key] = base64.b64decode(value, validate=True).decode("utf-8")
        except (binascii.Error, ValueError):
            values[key] = Unresolved(f"comes from {where} data that is not base64 UTF-8 text")
    for key, value in mapping(secret.get("stringData"), f"{where} stringData").items():
        values[key] = value
    return values


def container_env(container, namespace, sources, external, where, used):
    """The container's environment, with envFrom and value references resolved."""
    env = {}
    for entry in items_of(container.get("envFrom"), f"{where} envFrom"):
        entry = mapping(entry, f"{where} envFrom entry")
        refs = [(kind, entry[field]) for field, kind in (("configMapRef", "ConfigMap"), ("secretRef", "Secret"))
                if entry.get(field) is not None]
        if len(refs) != 1:
            raise InputError(f"{where}: every envFrom entry names one ConfigMap or Secret")
        kind, ref = refs[0]
        name = mapping(ref, f"{where} envFrom {kind}").get("name")
        values = sources.get((kind, namespace, name))
        if values is None:
            if f"{kind.lower()}/{name}" in external:
                used.add(f"{kind.lower()}/{name}")
                continue
            raise InputError(f"{where} takes its environment from {kind} {name}, which is not in the files read; "
                             f"pass --external-env {kind.lower()}/{name} if it is supplied elsewhere and sets "
                             "neither STATE_BACKEND nor DATABASE_POOL_MAX")
        prefix = entry.get("prefix") or ""
        for key, value in values.items():
            env[prefix + key] = value
    for entry in items_of(container.get("env"), f"{where} env"):
        entry = mapping(entry, f"{where} env entry")
        name = entry.get("name")
        if "valueFrom" in entry:
            value = Unresolved("is not a value or a key of a ConfigMap or Secret in the files read")
            source = mapping(entry["valueFrom"], f"{where} env {name} valueFrom")
            for field, kind in (("configMapKeyRef", "ConfigMap"), ("secretKeyRef", "Secret")):
                if source.get(field) is not None:
                    ref = mapping(source[field], f"{where} env {name} {field}")
                    values = sources.get((kind, namespace, ref.get("name")), {})
                    if ref.get("key") in values:
                        value = values[ref["key"]]
        else:
            value = entry.get("value")
            value = "" if value is None else value
        env[name] = value
    for name in SIZING_ENV:
        if isinstance(env.get(name), str) and "$(" in env[name]:
            env[name] = Unresolved("uses $(...) expansion, which the guard does not evaluate")
    return env


def container_argv(container, where):
    argv = []
    if container.get("command") is not None:
        command = string_list(container["command"], f"{where} command")
        if not command or command[0] not in GATEWAY_BINARIES:
            raise InputError(f"{where} replaces the gateway's entrypoint, so the guard cannot tell what it runs")
        argv = command[1:]
    if container.get("args") is not None:
        argv += string_list(container["args"], f"{where} args")
    if argv and "$(" in argv[0]:
        raise InputError(f"{where}: its command uses $(...) expansion, which the guard does not evaluate")
    return argv


def autoscaler_max(entry, where):
    if entry is None:
        return None
    kind, scaler, source = entry
    label = f"{source}: {kind}/{scaler['metadata']['name']}"
    if kind != "HorizontalPodAutoscaler":
        raise InputError(f"{where} is scaled by {label}; the guard reads only HorizontalPodAutoscaler maxReplicas")
    spec = mapping(scaler.get("spec"), f"{label} spec")
    maximum = count(spec.get("maxReplicas"), f"{label} maxReplicas", minimum=1)
    minimum = count(spec.get("minReplicas", 1), f"{label} minReplicas")
    if minimum > maximum:
        raise InputError(f"{label} minReplicas {minimum} exceeds maxReplicas {maximum}")
    return maximum


def rollout_surge(kind, workload, pods, where):
    """Pods a rollout may add on top of the ceiling, before any old one leaves."""
    if kind != "Deployment":
        return 0
    strategy = mapping(mapping(workload.get("spec"), f"{where} spec").get("strategy"), f"{where} strategy")
    if strategy.get("type", "RollingUpdate") == "Recreate":
        return 0
    if strategy.get("type", "RollingUpdate") != "RollingUpdate":
        raise InputError(f"{where} has an unknown rollout strategy {strategy.get('type')!r}")
    surge = mapping(strategy.get("rollingUpdate"), f"{where} rollingUpdate").get("maxSurge", "25%")
    if isinstance(surge, str) and re.fullmatch(r"(0|[1-9][0-9]*)%", surge):
        return (pods * int(surge[:-1]) + 99) // 100
    return count(surge, f"{where} maxSurge")


def job_instances(kind, workload, command, where):
    spec = mapping(workload.get("spec"), f"{where} spec")
    if kind == "Pod":
        return 1
    if kind == "Job":
        return max(count(spec.get("parallelism", 1), f"{where} parallelism"), 1)
    if kind == "CronJob":
        if spec.get("concurrencyPolicy") != "Forbid":
            raise InputError(f"{where}: runs of this CronJob can overlap; set concurrencyPolicy: Forbid so one "
                             "budgeted run at a time is the most there can be")
        job = mapping(mapping(spec.get("jobTemplate"), f"{where} jobTemplate").get("spec"), f"{where} job spec")
        return max(count(job.get("parallelism", 1), f"{where} parallelism"), 1)
    raise InputError(f"{where}: a {kind} restarts `{command}` for ever; run one-shot commands from a Job")


def nested_mappings(item):
    """Every mapping inside an object, its own metadata aside."""
    stack = [value for key, value in item.items() if key not in ("apiVersion", "kind", "metadata")]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            yield node
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)


def container_like(node):
    """A mapping shaped like a container: an image, or an environment."""
    return isinstance(node.get("image"), str) or any(isinstance(node.get(key), list) for key in ("env", "envFrom"))


def kubernetes_facts(documents, external=()):
    """Gateway pools, one-shot jobs and uncounted workloads in rendered manifests.

    `documents` is (source, document) pairs; `external` names envFrom sources
    supplied outside these files that the operator declares set neither
    sizing variable.
    """
    sources, scalers, workloads, others, seen = {}, [], [], [], {}
    for source, item in kubernetes_objects(documents):
        if not isinstance(item, dict):
            raise InputError(f"{source}: every document must be a Kubernetes object")
        kind, metadata = item.get("kind"), mapping(item.get("metadata"), f"{source}: metadata")
        name, namespace = metadata.get("name"), metadata.get("namespace") or ""
        if not isinstance(kind, str) or not isinstance(name, str) or not name:
            raise InputError(f"{source}: every object needs a kind and a metadata.name")
        if kind == "Kustomization":
            raise InputError(f"{source} is a Kustomization; render it with `kubectl kustomize` and check the output")
        if (kind, namespace, name) in seen:
            raise InputError(f"{source}: {kind}/{name} is also defined in {seen[(kind, namespace, name)]}")
        seen[(kind, namespace, name)] = source
        where = f"{source}: {kind}/{name}"
        if kind == "ConfigMap":
            sources[(kind, namespace, name)] = mapping(item.get("data"), f"{where} data")
        elif kind == "Secret":
            sources[(kind, namespace, name)] = secret_values(item, where)
        spec = item.get("spec")
        if isinstance(spec, dict) and spec.get("scaleTargetRef") is not None:
            target = mapping(spec["scaleTargetRef"], f"{where} scaleTargetRef")
            scalers.append((target.get("kind"), namespace, target.get("name"), (kind, item, source)))
        if kind in POD_TEMPLATES:
            workloads.append((source, kind, namespace, name, item))
        else:
            others.append((source, kind, namespace, name, item))

    def same_namespace(one, other):
        # An object without a namespace lands in whichever one it is applied
        # to, so it may be the same namespace as any other.
        return one == other or "" in (one, other)

    def scaler_for(kind, namespace, name, where):
        # A KEDA ScaledObject may leave the target's kind out (it means a
        # Deployment), so a missing kind matches any workload.
        found = [entry for target_kind, scope, target, entry in scalers
                 if target_kind in (kind, None) and target == name and same_namespace(scope, namespace)]
        if len(found) > 1:
            raise InputError(f"{where} is scaled by both {found[0][0]}/{found[0][1]['metadata']['name']} and "
                             f"{found[1][0]}/{found[1][1]['metadata']['name']}")
        return found[0] if found else None

    facts = {"pools": [], "jobs": [], "uncounted": [], "uncounted_files": {}, "external": set()}
    for source, kind, namespace, name, item in others:
        # A kind the guard does not model (a Knative Service, an Argo Rollout
        # with a template, an OpenShift Template) may still run gateway
        # containers; refuse one that runs them in cluster mode.
        if kind in ("ConfigMap", "Secret"):
            continue
        for container in nested_mappings(item):
            if not container_like(container):
                continue
            where = f"{source}: {kind}/{name} container {container.get('name')}"
            env = container_env(container, namespace, sources, external, where, facts["external"])
            if backend_of(env, where) == "postgres":
                raise InputError(f"{where} runs the gateway in cluster mode, and the guard cannot bound a "
                                 f"{kind}'s replicas; run serving replicas from a Deployment or StatefulSet")
    cluster_workloads = []
    for source, kind, namespace, name, workload in workloads:
        label = f"{kind}/{name}"
        pod = workload
        for field in POD_TEMPLATES[kind]:
            pod = mapping(pod.get(field) if isinstance(pod, dict) else None, f"{source}: {label} pod template")
        counted = False
        containers = items_of(pod.get("initContainers"), f"{source}: {label} initContainers")
        for container in containers + items_of(pod.get("containers"), f"{source}: {label} containers"):
            container = mapping(container, f"{source}: {label} container")
            where = f"{source}: {label} container {container.get('name')}"
            env = container_env(container, namespace, sources, external, where, facts["external"])
            if backend_of(env, where) != "postgres":
                continue
            counted = True
            argv = container_argv(container, where)
            entry_name = f"{label} container {container.get('name')}"
            if argv:
                command = command_of(argv, where)
                facts["jobs"].append({"name": entry_name, "command": command, "file": source,
                                      "instances": job_instances(kind, workload, command, where)})
                continue
            if kind not in ("Deployment", "StatefulSet"):
                raise InputError(f"{where}: a {kind} serving the gateway has no replica count the guard can "
                                 "bound; run serving replicas from a Deployment or StatefulSet")
            spec = mapping(workload.get("spec"), f"{where} spec")
            replicas = 1 if spec.get("replicas") is None else count(spec["replicas"], f"{source}: {label} replicas")
            maximum = autoscaler_max(scaler_for(kind, namespace, name, where), where)
            pods = max(replicas, maximum or 0)
            pool_max, origin = pool_max_of(env, where)
            facts["pools"].append({"name": entry_name, "file": source, "replicas": replicas,
                                   "autoscaler_max": maximum, "surge": rollout_surge(kind, workload, pods, where),
                                   "pool_max": pool_max, "pool_origin": origin})
        if counted:
            cluster_workloads.append((kind, namespace, name, f"{source}: {label}"))
        else:
            facts["uncounted"].append(label)
            facts["uncounted_files"][label] = source
    for source, kind, namespace, name, item in others:
        # A kind the guard does not model may run pods from a workload it
        # names rather than embeds: an Argo Rollout's workloadRef (whose
        # Deployment Argo scales to 0 while the Rollout runs its own pods), a
        # Flagger Canary's targetRef (which Flagger clones into a primary and
        # runs beside it), a VerticalPodAutoscaler's targetRef (which evicts
        # and replaces pods). The HorizontalPodAutoscaler is the one modelled.
        if kind == "HorizontalPodAutoscaler":
            continue
        for ref in nested_mappings(item):
            ref_kind, ref_name = ref.get("kind"), ref.get("name")
            if not isinstance(ref_kind, str) or not isinstance(ref_name, str):
                continue
            ref_namespace = ref.get("namespace") if isinstance(ref.get("namespace"), str) else namespace
            for target_kind, target_namespace, target_name, label in cluster_workloads:
                if (ref_kind.lower(), ref_name) == (target_kind.lower(), target_name) \
                        and same_namespace(ref_namespace, target_namespace):
                    raise InputError(f"{source}: {kind}/{name} refers to {label}, which runs the gateway in cluster "
                                     f"mode, and the guard does not model how a {kind} runs or scales that "
                                     "workload's pods; run serving replicas from a Deployment or StatefulSet that "
                                     "nothing else manages")
    return facts


# ---------------------------------------------------------------------------
# The arithmetic.


def plan(source, server, pooler, pooler_connections, facts, headroom, server_service=None, ignored_servers=()):
    """Validate one deployment's inputs; `headroom` maps names to declared values."""
    if server is None:
        raise InputError(f"{source}: the server's limits are unknown; pass --max-connections, "
                         "--superuser-reserved-connections and --reserved-connections")
    values = {key: value for key, (value, _) in server.items()}
    if values["max_connections"] < 1 or values["max_connections"] > MAX_CONNECTIONS_LIMIT:
        raise InputError(f"{source}: max_connections must be between 1 and {MAX_CONNECTIONS_LIMIT}")
    if values["superuser_reserved_connections"] + values["reserved_connections"] >= values["max_connections"]:
        raise InputError(f"{source}: superuser_reserved_connections plus reserved_connections must be less than "
                         "max_connections, or PostgreSQL refuses to start")
    if pooler not in POOLER_MODES:
        raise InputError(f"{source}: the pooler mode must be one of {', '.join(POOLER_MODES)}")
    if (pooler == "session") != (pooler_connections is not None):
        raise InputError(f"{source}: the pooler's server connections are required with a session pooler and "
                         "meaningless without one")
    if pooler_connections is not None:
        pooler_connections = count(pooler_connections, f"{source}: the pooler's server connections")
    unknown = set(headroom) - set(HEADROOM_NAMES)
    if unknown:
        raise InputError(f"{source}: unknown headroom {', '.join(sorted(unknown))}")
    entries = {}
    for name, default, _ in HEADROOM:
        if name in headroom and headroom[name] is not None:
            entries[name] = (count(headroom[name], f"{source}: the {name} headroom"), "declared")
        elif default is not None:
            entries[name] = (default, "default")
        else:
            raise InputError(f"{source}: name the {name} headroom, even if it is 0")
    return {"source": source, "server": server, "pooler": pooler, "pooler_connections": pooler_connections,
            "pools": facts["pools"], "jobs": facts["jobs"], "uncounted": facts["uncounted"],
            "server_service": server_service, "ignored_servers": list(ignored_servers),
            "external": sorted(facts.get("external", ())), "headroom": entries}


def decide(budget):
    server = {key: value for key, (value, _) in budget["server"].items()}
    available = (server["max_connections"] - server["superuser_reserved_connections"]
                 - server["reserved_connections"])
    pods = sum(max(pool["replicas"], pool["autoscaler_max"] or 0) + pool["surge"] for pool in budget["pools"])
    pool_connections = sum((max(pool["replicas"], pool["autoscaler_max"] or 0) + pool["surge"]) * pool["pool_max"]
                           for pool in budget["pools"])
    headroom = sum(value for value, _ in budget["headroom"].values())
    problems, advice, notes = [], [], []
    required = {}
    for job in budget["jobs"]:
        name, connections = COMMANDS[job["command"]]
        required[name] = required.get(name, 0) + connections * job["instances"]
    for name, needed in sorted(required.items()):
        have = budget["headroom"][name][0]
        if have < needed:
            problems.append(f"the {name} headroom is {have}, but the deployment's own `{name}` jobs can hold "
                            f"{needed} connections at once; budget at least {needed}")
    server_side = pool_connections
    if budget["pooler"] in ("transaction", "statement"):
        problems.append(f"{budget['pooler']} pooling breaks the gateway: its pooled sessions carry search_path and "
                        "server-side timeouts as startup parameters, and migrate up, the maintenance pass and the "
                        "discovery projector hold session-scoped advisory locks; use session pooling or connect "
                        "directly")
    elif budget["pooler"] == "session":
        server_side = budget["pooler_connections"]
        if pool_connections > server_side:
            problems.append(f"the pooler can hold {server_side} server sessions but the gateway pools can ask for "
                            f"{pool_connections}; in session mode each gateway connection keeps a server session "
                            "for its lifetime, so the rest wait at the pooler and time out acquiring")
        notes.append("jobs and headroom clients are counted as connecting directly; one routed through the pooler "
                     "is already inside the pooler's server connections")
    total = server_side + headroom
    if total > available:
        problems.append(f"the deployment can ask for {total} connections and the server allows {available} to "
                        f"ordinary roles: over by {total - available}")
        spare_for_pools = available - headroom
        if budget["pooler"] == "none" and pods:
            largest = spare_for_pools // pods
            if largest >= 1:
                advice.append(f"lower DATABASE_POOL_MAX to {largest} on every serving replica "
                              f"({pods} pods x {largest} + {headroom} = {pods * largest + headroom})")
            else:
                advice.append(f"no DATABASE_POOL_MAX fits {pods} pods: the headroom alone leaves "
                              f"{plural(max(spare_for_pools, 0), 'connection')}")
            sizes = {pool["pool_max"] for pool in budget["pools"]}
            size = sizes.pop() if len(sizes) == 1 else None
            fitting = max(spare_for_pools, 0) // size if size else 0
            if fitting >= 1:
                advice.append(f"or run at most {fitting} gateway pods at once, counting the autoscaler maximum and "
                              f"rollout surge ({fitting} x {size} + {headroom} = {fitting * size + headroom})")
        minimum = total + server["superuser_reserved_connections"] + server["reserved_connections"]
        advice.append(f"or raise max_connections to at least {minimum}, after checking the server's memory and "
                      "its own limits; every connection costs the server memory whether or not it is used")
    if budget["pools"]:
        notes.append("a gateway that is shutting down keeps its pool until it exits and is not in this count "
                     "(Kubernetes does not count a terminating pod against maxSurge either); keep spare for a "
                     "rollout or scale-down that replaces gateways faster than they drain")
    if any("not on the service's command line" in origin for _, origin in budget["server"].values()):
        notes.append("a setting the server's command line does not pass is taken as PostgreSQL's default, but its "
                     "configuration files can change it; SHOW it on the running server")
    smallest = min((pool["pool_max"] for pool in budget["pools"]), default=None)
    if smallest is not None and smallest <= 2:
        notes.append(f"the maintenance leader's dedicated pass session comes out of its own pool, so a pool of "
                     f"{smallest} leaves the leader {smallest - 1} for requests while a pass runs")
    return {**budget, "status": "rejected" if problems else "fits", "available": available, "pods": pods,
            "pool_connections": pool_connections, "server_side": server_side, "headroom_total": headroom,
            "total": total, "spare": available - total, "required": required, "problems": problems,
            "advice": advice, "notes": notes}


def plural(number, word):
    return f"{number} {word}" + ("" if number == 1 else "s")


def describe_pool(pool):
    parts = [plural(pool["replicas"], "replica")]
    if pool["autoscaler_max"] is not None:
        parts.append(f"autoscaler maximum {pool['autoscaler_max']}")
    parts.append(f"rollout surge {pool['surge']}")
    pods = max(pool["replicas"], pool["autoscaler_max"] or 0) + pool["surge"]
    origin = "" if pool["pool_origin"] == "DATABASE_POOL_MAX" else f", {pool['pool_origin']}"
    return (pods * pool["pool_max"],
            f"{plural(pods, 'pod')} x DATABASE_POOL_MAX {pool['pool_max']}{origin} ({', '.join(parts)})")


def render(result):
    row = "  {:<34}{:>7}  {}".format
    lines = [f"PostgreSQL connection budget: {result['source']}", "",
             "Server" + (f" (service {result['server_service']})" if result.get("server_service") else "")]
    for key in SERVER_SETTINGS:
        value, origin = result["server"][key]
        lines.append(row(key, value, origin))
    lines.append(row("available to ordinary roles", result["available"],
                     "max_connections - superuser_reserved_connections - reserved_connections"))
    if result["ignored_servers"]:
        lines.append(f"  ignored, runs PostgreSQL that is not the gateways' server: "
                     f"{', '.join(result['ignored_servers'])}")
    lines += ["", f"Gateway pools (pooler: {result['pooler']})"]
    for pool in result["pools"]:
        connections, detail = describe_pool(pool)
        lines.append(row(pool["name"], connections, detail))
    if not result["pools"]:
        lines.append(row("no serving replicas", 0, ""))
    if result["pooler"] == "session":
        lines.append(row("pooler server connections", result["pooler_connections"],
                         "counted on the server in place of the pools"))
    lines += ["", "Headroom"]
    for name, _, description in HEADROOM:
        value, origin = result["headroom"][name]
        lines.append(row(name, value, f"{origin}: {description}"))
    for job in result["jobs"]:
        name, connections = COMMANDS[job["command"]]
        lines.append(f"    {name} covers {job['name']} (`{job['command']}`, {connections} x {job['instances']})")
    if result["uncounted"]:
        lines.append(f"  not counted, open no gateway pool: {', '.join(result['uncounted'])}")
    if result["external"]:
        lines.append(f"  declared external, set no sizing variable: {', '.join(result['external'])}")
    lines.append("")
    if result["status"] == "fits":
        lines.append(f"FITS: {result['server_side']} + {result['headroom_total']} = {result['total']} of "
                     f"{result['available']} connections, {result['spare']} spare")
    else:
        lines.append(f"REJECTED: {result['server_side']} + {result['headroom_total']} = {result['total']} of "
                     f"{result['available']} connections")
        lines += [f"  - {problem}" for problem in result["problems"]]
        if result["advice"]:
            lines.append("  To fit:")
            lines += [f"  - {advice}" for advice in result["advice"]]
    lines += [f"  note: {note}" for note in result["notes"]]
    return "\n".join(lines)


def json_ready(result):
    value = dict(result)
    value["server"] = {key: {"value": number, "origin": origin} for key, (number, origin) in result["server"].items()}
    value["headroom"] = {key: {"value": number, "origin": origin}
                         for key, (number, origin) in result["headroom"].items()}
    return value


# ---------------------------------------------------------------------------
# The shipped examples.


def relative(path, root):
    return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()


def kustomize_inputs(root, path, document, files):
    """The patch files of a shipped Kustomization, after checking its shape."""
    source = relative(path, root)
    unknown = set(document) - KUSTOMIZATION_KEYS
    if unknown:
        raise InputError(f"{source} uses {', '.join(sorted(unknown))}, which can change sizing inputs; the guard "
                         "accepts resources and sizing-neutral patches only")
    for resource in items_of(document.get("resources"), f"{source} resources"):
        target = (Path(path).parent / str(resource)).resolve()
        if target.is_dir():
            target = next((target / name for name in ("kustomization.yaml", "kustomization.yml")
                           if (target / name).is_file()), target)
        if target not in files:
            raise InputError(f"{source}: resource {resource} is not a shipped example the guard reads")
    patches = set()
    for entry in items_of(document.get("patches"), f"{source} patches"):
        entry = mapping(entry, f"{source} patch")
        if set(entry) - {"path", "target"} or not isinstance(entry.get("path"), str):
            raise InputError(f"{source}: the guard reads strategic-merge patches from files only")
        target = (Path(path).parent / entry["path"]).resolve()
        if target not in files:
            raise InputError(f"{source}: patch {entry['path']} is not a shipped example the guard reads")
        patches.add(target)
    return patches


def touches_sizing(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if key in PATCH_SIZING_FIELDS or key in SIZING_ENV or str(key).startswith("$"):
                return True
            if key == "env" and isinstance(value, list):
                if any(isinstance(entry, dict) and entry.get("name") in SIZING_ENV for entry in value):
                    return True
            if touches_sizing(value):
                return True
    elif isinstance(node, list):
        return any(touches_sizing(item) for item in node)
    return False


def kubernetes_examples(root, paths):
    """(source, document) pairs of the shipped manifests, patches set aside."""
    files = {Path(path).resolve() for path in paths}
    loaded = {path: load_documents(path, relative(path, root)) for path in sorted(files)}
    patches = set()
    for path, documents in loaded.items():
        for document in documents:
            if isinstance(document, dict) and document.get("kind") == "Kustomization":
                patches |= kustomize_inputs(root, path, document, files)
    pairs = []
    for path, documents in loaded.items():
        source = relative(path, root)
        for document in documents:
            if path in patches:
                if not isinstance(document, dict) or touches_sizing(document):
                    raise InputError(f"{source} patches a sizing input; render the overlay with `kubectl kustomize` "
                                     "and check the output")
            elif not (isinstance(document, dict) and document.get("kind") == "Kustomization"):
                pairs.append((source, document))
    return pairs


def compare_rendered(ours, theirs, source):
    """Fail unless Compose's own rendering yields the same sizing facts."""
    for key in ("pools", "jobs", "uncounted", "servers"):
        mine, rendered = ours[key], theirs[key]
        if isinstance(mine, list):
            mine, rendered = (sorted(json.dumps(item, sort_keys=True) for item in value) for value in (mine, rendered))
        if json.dumps(mine, sort_keys=True) != json.dumps(rendered, sort_keys=True):
            raise InputError(f"{source}: the guard reads {key} differently from Compose's rendering of the file; "
                             "the guard's YAML reader and Compose disagree, so the reading cannot be trusted")


def example_result(source, facts):
    if not facts["pools"] and not facts["jobs"]:
        return {"source": source, "status": "standalone", "uncounted": facts["uncounted"]}
    budget = EXAMPLE_BUDGETS.get(source)
    if budget is None:
        raise InputError(f"{source} runs the gateway in cluster mode, and EXAMPLE_BUDGETS in "
                         "scripts/pool_sizing.py names no connection budget for it")
    keys = set(budget)
    allowed = {"pooler", "pooler_connections", "headroom", "uncounted", "server", "server_service"}
    if not {"pooler", "headroom", "uncounted"} <= keys <= allowed or ("server" in keys) == ("server_service" in keys):
        raise InputError(f"{source}: its EXAMPLE_BUDGETS entry needs pooler, headroom, uncounted and exactly one of "
                         "server (the limits of the server its gateways use) or server_service (the service in "
                         "the file that is that server), and may add only pooler_connections")
    if sorted(facts["uncounted"]) != sorted(budget["uncounted"]):
        raise InputError(f"{source}: {sorted(facts['uncounted'])} open no gateway pool, but the reviewed list is "
                         f"{sorted(budget['uncounted'])}; budget a new database client before it ships")
    if "server_service" in budget and "servers" not in facts:
        raise InputError(f"{source}: server_service names a Compose service, and this is not a Compose file")
    declared = None
    if "server" in budget:
        if not isinstance(budget["server"], dict) or set(budget["server"]) != set(SERVER_SETTINGS):
            raise InputError(f"{source}: its EXAMPLE_BUDGETS server must name the server's "
                             f"{', '.join(SERVER_SETTINGS)}")
        declared = {key: count(budget["server"][key], f"{source} budget {key}") for key in SERVER_SETTINGS}
    server, server_service, ignored = select_server(facts, source, budget.get("server_service"), declared,
                                                    "example budget")
    return decide(plan(source, server, budget["pooler"], budget.get("pooler_connections"), facts,
                       budget["headroom"], server_service, ignored))


def compose_files(directory):
    return sorted({path for pattern in ("docker-compose*.y*ml", "compose*.y*ml") for path in directory.glob(pattern)})


def read_compose(path, source):
    documents = load_documents(path, source)
    if len(documents) != 1:
        raise InputError(f"{source}: a Compose file is exactly one document")
    refuse_compose_overrides(path)
    return compose_facts(documents[0], source)


def examples(root=ROOT, rendered=None):
    """Check every shipped deployment example; `rendered` maps sources to Compose's JSON."""
    root = Path(root)
    rendered = dict(rendered or {})
    results = []
    for path in compose_files(root / "docs/deployment"):
        source = relative(path, root)
        facts = read_compose(path, source)
        if source in rendered:
            theirs = load_documents(rendered.pop(source), f"{source} (rendered)")
            if len(theirs) != 1:
                raise InputError(f"{source} (rendered): a Compose file is exactly one document")
            compare_rendered(facts, compose_facts(theirs[0], f"{source} (rendered)"), source)
        results.append(example_result(source, facts))
    if rendered:
        raise InputError(f"--rendered names {', '.join(sorted(rendered))}, which is not a Compose example in "
                         "docs/deployment")
    # The repository-root Compose files are overlays, combined with -f, so no
    # one file's budget is the stack's. Each must stay standalone: then no
    # combination of them can select cluster mode either.
    for path in compose_files(root):
        source = relative(path, root)
        facts = read_compose(path, source)
        if facts["pools"] or facts["jobs"]:
            raise InputError(f"{source} runs the gateway in cluster mode, but the repository-root Compose files are "
                             "overlays combined with -f; ship a cluster-mode example as one file in docs/deployment "
                             "with a budget in EXAMPLE_BUDGETS")
        results.append({"source": source, "status": "standalone", "uncounted": facts["uncounted"]})
    paths = sorted((root / "deploy").rglob("*.y*ml"))
    pairs = kubernetes_examples(root, paths)
    facts = kubernetes_facts(pairs)
    for source in sorted({relative(path, root) for path in paths}):
        mine = {"pools": [pool for pool in facts["pools"] if pool["file"] == source],
                "jobs": [job for job in facts["jobs"] if job["file"] == source],
                "uncounted": [label for label, file in facts["uncounted_files"].items() if file == source]}
        if mine["pools"] or mine["jobs"] or mine["uncounted"]:
            results.append(example_result(source, mine))
    budgeted = {result["source"] for result in results if result["status"] != "standalone"}
    stale = sorted(set(EXAMPLE_BUDGETS) - budgeted)
    if stale:
        raise InputError(f"EXAMPLE_BUDGETS names {', '.join(stale)}, which no shipped example runs in cluster mode")
    return results


# ---------------------------------------------------------------------------
# Command line.


def plain_count(text):
    if not re.fullmatch(r"0|[1-9][0-9]*", text):
        raise argparse.ArgumentTypeError(f"expected a whole number written plainly, got {text!r}")
    return int(text)


def check_arguments(args):
    sources = [bool(args.compose), bool(args.kubernetes), args.replicas is not None]
    if sum(sources) != 1:
        raise InputError("give exactly one of --compose FILE, --kubernetes FILE or --replicas N")
    manual = {"--autoscaler-max": args.autoscaler_max, "--surge": args.surge, "--pool-max": args.pool_max}
    if args.replicas is None and any(value is not None for value in manual.values()):
        raise InputError(f"{', '.join(k for k, v in manual.items() if v is not None)} describe replicas given by "
                         "hand; a deployment file is the source of its own replica counts")
    if args.external_env and not args.kubernetes:
        raise InputError("--external-env applies to Kubernetes manifests only")
    if args.server_service is not None and not args.compose:
        raise InputError("--server-service names a service of a Compose file; give the server's limits instead")
    for entry in args.external_env:
        if not re.fullmatch(r"(configmap|secret)/[^/\s]+", entry):
            raise InputError(f"--external-env expects configmap/NAME or secret/NAME, got {entry!r}")
    if args.replicas is not None:
        if args.surge is None:
            raise InputError("name the rollout surge with --surge, even if it is 0")
        pool_max = DEFAULT_POOL_MAX if args.pool_max is None else args.pool_max
        if not 1 <= pool_max <= MAX_POOL_MAX:
            raise InputError(f"--pool-max must be between 1 and {MAX_POOL_MAX}, as the gateway requires")
        if args.replicas < 1 or (args.autoscaler_max is not None and args.autoscaler_max < 1):
            raise InputError("--replicas and --autoscaler-max must be at least 1")
        facts = {"pools": [{"name": "gateway replicas", "replicas": args.replicas,
                            "autoscaler_max": args.autoscaler_max, "surge": args.surge, "pool_max": pool_max,
                            "pool_origin": "DATABASE_POOL_MAX" if args.pool_max is not None else "gateway default"}],
                 "jobs": [], "uncounted": []}
        source = "command line"
    elif args.compose:
        documents = load_documents(args.compose, args.compose)
        if len(documents) != 1:
            raise InputError(f"{args.compose}: a Compose file is exactly one document")
        refuse_compose_overrides(args.compose)
        facts, source = compose_facts(documents[0], args.compose), args.compose
    else:
        pairs = [(path, document) for path in args.kubernetes for document in load_documents(path, path)]
        facts, source = kubernetes_facts(pairs, set(args.external_env)), ", ".join(args.kubernetes)
    flags = {"max_connections": args.max_connections,
             "superuser_reserved_connections": args.superuser_reserved_connections,
             "reserved_connections": args.reserved_connections}
    given = [key for key, value in flags.items() if value is not None]
    if given and len(given) != len(flags):
        raise InputError("name the server's limits with all of --max-connections, --superuser-reserved-connections "
                         "and --reserved-connections (0 before PostgreSQL 16); check them with SHOW")
    server, server_service, ignored = select_server(facts, source, args.server_service, flags if given else None,
                                                    "declared")
    headroom = {name: getattr(args, name) for name in HEADROOM_NAMES}
    return decide(plan(source, server, args.pooler, args.pooler_server_connections, facts, headroom,
                       server_service, ignored))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="check one deployment against its server's limits")
    source = check.add_argument_group("the deployment (give exactly one)")
    source.add_argument("--compose", metavar="FILE",
                        help="a Compose file, or `docker compose config --format json` output")
    source.add_argument("--kubernetes", metavar="FILE", action="append", default=[],
                        help="rendered Kubernetes manifests, YAML or JSON; repeat for several files")
    source.add_argument("--replicas", type=plain_count, help="serving replicas, by hand")
    check.add_argument("--autoscaler-max", type=plain_count, help="with --replicas: the autoscaler's maximum")
    check.add_argument("--surge", type=plain_count, help="with --replicas: pods a rollout may add")
    check.add_argument("--pool-max", type=plain_count, help=f"with --replicas: DATABASE_POOL_MAX (default "
                       f"{DEFAULT_POOL_MAX})")
    check.add_argument("--external-env", metavar="KIND/NAME", action="append", default=[],
                       help="an envFrom configmap/NAME or secret/NAME supplied elsewhere that sets neither "
                       "STATE_BACKEND nor DATABASE_POOL_MAX")
    server = check.add_argument_group("the server (SHOW each one, or confirm a Compose service)")
    server.add_argument("--server-service", metavar="NAME",
                        help="with --compose: the PostgreSQL service in the file that the gateways use; its "
                        "command line supplies the server's limits")
    server.add_argument("--max-connections", type=plain_count)
    server.add_argument("--superuser-reserved-connections", type=plain_count)
    server.add_argument("--reserved-connections", type=plain_count, help="0 before PostgreSQL 16")
    check.add_argument("--pooler", required=True, choices=POOLER_MODES,
                       help="how the gateway reaches PostgreSQL: directly (none) or through a pooler")
    check.add_argument("--pooler-server-connections", type=plain_count,
                       help="with a session pooler: the most server connections it can open")
    headroom = check.add_argument_group("headroom (connections each consumer can hold at once)")
    for name, default, description in HEADROOM:
        suffix = f" (default {default})" if default is not None else " (required)"
        headroom.add_argument(f"--{name}", type=plain_count, help=description + suffix)
    check.add_argument("--json", action="store_true", help="print the decision as JSON")
    shipped = commands.add_parser("examples", help="check every shipped deployment example")
    shipped.add_argument("--rendered", metavar="SOURCE=JSON", action="append", default=[],
                         help="Compose's rendering of a shipped Compose example, which the guard's reading must match")
    shipped.add_argument("--json", action="store_true", help="print the decisions as JSON")
    args = parser.parse_args(argv)
    try:
        if args.command == "check":
            results = [check_arguments(args)]
        else:
            rendered = {}
            for entry in args.rendered:
                name, separator, path = entry.partition("=")
                if not separator or not name or not path:
                    raise InputError(f"--rendered expects SOURCE=JSON, got {entry!r}")
                rendered[name] = path
            results = examples(ROOT, rendered)
    except InputError as error:
        print(f"pool sizing: invalid input: {error}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps([json_ready(r) if r["status"] != "standalone" else r for r in results], indent=2))
    else:
        for result in results:
            if result["status"] == "standalone":
                print(f"{result['source']}: no cluster-mode gateway, so no PostgreSQL pool to budget")
            else:
                print(render(result))
            print()
    return 1 if any(result["status"] == "rejected" for result in results) else 0


if __name__ == "__main__":
    sys.exit(main())
