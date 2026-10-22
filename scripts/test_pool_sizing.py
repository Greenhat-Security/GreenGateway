"""Boundary, reader and shipped-example regressions for the pool sizing guard."""
import base64
import contextlib
import io
import json
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from unittest import mock

import pool_sizing as sizing

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_EXAMPLE = "docs/deployment/docker-compose.ha.yml"
SERVER = ["--max-connections", "100", "--superuser-reserved-connections", "3", "--reserved-connections", "0"]
HEADROOM = ["--backup", "1", "--monitoring", "1", "--operator", "2", "--other", "0"]
DIRECT = ["--pooler", "none"] + HEADROOM


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = sizing.main(list(args))
        except SystemExit as exit:
            # argparse refuses malformed flags itself, with the same status.
            code = exit.code
    return code, out.getvalue(), err.getvalue()


def parse(text):
    return sizing._Yaml(text, "fixture.yaml").documents()


def decision(*args):
    code, out, err = run("check", *args, "--json")
    if code == 2:
        raise AssertionError(err)
    return code, json.loads(out)[0]


class Files(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
        return str(path)

    def assertInvalid(self, args, pattern):
        code, out, err = run(*args)
        self.assertEqual(code, 2, out + err)
        self.assertRegex(err, pattern)
        self.assertEqual(out, "")


class ReaderTests(unittest.TestCase):
    def test_block_collections_scalars_and_comments(self):
        document, = parse(
            "# leading comment\n"
            "services:\n"
            "  db:\n"
            "    image: postgres:16@sha256:abc  # pinned\n"
            "    command:\n"
            "      - postgres\n"
            "      - -c\n"
            "      - max_connections=100\n"
            "  probe:\n"
            "    url: http://db:5432/x\n"
            "    test: [CMD, 'a b', \"c\", ]\n"
            "    labels: {tier: data, 'k.v/x': \"y\"}\n"
            "    empty: {}\n"
            "items:\n"
            "- plain\n"
            "- name: first\n"
            "  value: 'it''s'\n"
            "- - nested\n"
            "  - again\n"
            "-\n"
            "  late: entry\n"
            "nulls: [~, null]\n"
            "blank:\n"
            "quoted: \"tab\\there \\u00e9\\x41\"\n"
            "hash: a#b\n")
        self.assertEqual(document["services"]["db"]["image"], "postgres:16@sha256:abc")
        self.assertEqual(document["services"]["db"]["command"], ["postgres", "-c", "max_connections=100"])
        self.assertEqual(document["services"]["probe"]["url"], "http://db:5432/x")
        self.assertEqual(document["services"]["probe"]["test"], ["CMD", "a b", "c"])
        self.assertEqual(document["services"]["probe"]["labels"], {"tier": "data", "k.v/x": "y"})
        self.assertEqual(document["services"]["probe"]["empty"], {})
        self.assertEqual(document["items"], ["plain", {"name": "first", "value": "it's"}, ["nested", "again"],
                                             {"late": "entry"}])
        self.assertEqual(document["nulls"], [None, None])
        self.assertIsNone(document["blank"])
        self.assertEqual(document["quoted"], "tab\there \u00e9A")
        self.assertEqual(document["hash"], "a#b")

    def test_block_scalars_follow_literal_folded_and_chomping_rules(self):
        document, = parse(
            "literal: |\n  one\n  two\n\n  three\n"
            "strip: |-\n  kept\n\n"
            "keep: |+\n  kept\n\n"
            "folded: >\n  one\n  two\n\n  three\n    more\n  four\n"
            "folded_strip: >-\n  [{\"id\":\"x\"}]\n"
            "after: done\n"
            "in_sequence:\n  - |\n    line\n  - >-\n    a\n    b\n")
        self.assertEqual(document["literal"], "one\ntwo\n\nthree\n")
        self.assertEqual(document["strip"], "kept")
        self.assertEqual(document["keep"], "kept\n\n")
        self.assertEqual(document["folded"], "one two\nthree\n  more\nfour\n")
        self.assertEqual(document["folded_strip"], '[{"id":"x"}]')
        self.assertEqual(document["after"], "done")
        self.assertEqual(document["in_sequence"], ["line\n", "a b"])

    def test_anchors_aliases_and_merge_keys(self):
        document, = parse(
            "base: &base\n  A: '1'\n  B: '2'\n"
            "copy: *base\n"
            "service:\n  <<: *base\n  B: '3'\n"
            "scalar: &word hello\n"
            "again: *word\n")
        self.assertEqual(document["copy"], {"A": "1", "B": "2"})
        self.assertEqual(document["service"], {"A": "1", "B": "3"})
        self.assertEqual(document["again"], "hello")

    def test_documents_split_on_markers_and_skip_empty_ones(self):
        self.assertEqual(parse("---\na: 1\n---\n# only a comment\n---\nb: 2\n...\n"), [{"a": "1"}, {"b": "2"}])

    def test_ambiguous_or_unsupported_yaml_is_refused(self):
        cases = [
            ("a:\n\tb: 1\n", "tabs cannot indent"),
            ("a: !!int 3\n", "tags are not supported"),
            ("%YAML 1.2\n---\na: 1\n", "directives"),
            ("? a\n: b\n", "complex mapping keys|expected a mapping entry"),
            ("a: 1\na: 2\n", "duplicate key 'a'"),
            ("a: *missing\n", "unknown alias"),
            ("a: one\n  two\n", "cannot continue on a more indented line"),
            ("a: 'one\n  two'\n", "must close on its own line"),
            ("a: [1,\n  2]\n", "flow collection must close"),
            ("a: [[1]]\n", "nested flow collections"),
            ("a: {? b : c}\n", "unsupported indicator"),
            ("a: [x #y]\n", "comment cannot sit inside a flow collection"),
            ("--- a: 1\n", "document marker line"),
            ("a: |2\n  x\n", "indentation indicators"),
            ("a: b: c\n", "cannot contain ': '"),
            ("a: - b\n", "sequence cannot start on its key's line"),
            ("a: \"\\q\"\n", "invalid escape"),
            ("a: @x\n", "reserved indicator"),
            ("<<: [1]\n", "unsupported indicator|merge key needs a mapping"),
            ("a:\n  b: 1\n c: 2\n", "unexpected"),
            ("a: 1\n- b\n", "unexpected content"),
        ]
        for text, message in cases:
            with self.subTest(text=text):
                with self.assertRaisesRegex(sizing.InputError, message):
                    parse(text)

    def test_flow_mapping_keys_end_only_at_a_value_indicator(self):
        # A plain key's ':' is a value indicator only when a space, a tab or
        # the end of the line follows it; otherwise it belongs to the key.
        document, = parse("a: {k8s.io/x:y: v, url: http://h:80/p, 'q': \"r\"}\n"
                          "b: [http://h:80/p, a:b]\n"
                          "c: {x : y, z: }\n")
        self.assertEqual(document["a"], {"k8s.io/x:y": "v", "url": "http://h:80/p", "q": "r"})
        self.assertEqual(document["b"], ["http://h:80/p", "a:b"])
        self.assertEqual(document["c"], {"x": "y", "z": None})

    def test_flow_scalars_yaml_tools_split_differently_are_refused(self):
        cases = [
            # One key `DATABASE_POOL_MAX:5` with a null value to YAML, not a pool of 5.
            ("e: {STATE_BACKEND: postgres, DATABASE_POOL_MAX:5}\n", "expected ':' in a flow mapping"),
            ("e: {DATABASE_POOL_MAX:'5'}\n", "expected ':' in a flow mapping"),
            # A ':' before a flow indicator or after a space.
            ("e: {a:}\n", "beside a space or a flow indicator"),
            ("e: {a:, b: c}\n", "beside a space or a flow indicator"),
            ("e: {a :b}\n", "beside a space or a flow indicator"),
            ("e: [a:]\n", "beside a space or a flow indicator"),
            ("e: [a :b]\n", "beside a space or a flow indicator"),
            ("e: [a: b]\n", "cannot contain ': '"),
            # PyYAML ends a plain flow scalar at any '?'; go-yaml does not.
            ("e: [a?b]\n", "at a '?'"),
            ("e: {a: b?c}\n", "at a '?'"),
            # Indicators that cannot open a plain flow scalar.
            ("e: [:a]\n", "unsupported indicator ':'"),
            ("e: [- a]\n", "unsupported indicator '-'"),
            ("e: [a, , b]\n", "empty entry"),
            ("e: {, a: b}\n", "empty entry"),
        ]
        for text, message in cases:
            with self.subTest(text=text):
                with self.assertRaisesRegex(sizing.InputError, message):
                    parse(text)

    def test_characters_yaml_tools_read_differently_are_refused(self):
        for char in ("\r", "\x85", "\u2028", "\u2029", "\x0b", "\x0c", "\x1c", "\x7f", "\x00", "\ufeff"):
            with self.subTest(char=repr(char)):
                with self.assertRaisesRegex(sizing.InputError, r"fixture\.yaml:2: contains"):
                    parse("a: 1\nb: x" + char + "  c: 2\n")
        # CRLF line breaks are line breaks to every tool.
        self.assertEqual(parse("a: 1\r\nb:\r\n  c: 2\r\n"), [{"a": "1", "b": {"c": "2"}}])

    def test_a_byte_order_mark_may_only_open_the_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bom.yaml"
            path.write_bytes(b"\xef\xbb\xbfa: 1\n")
            self.assertEqual(sizing.load_documents(path, "bom"), [{"a": "1"}])
            path.write_bytes(b"\xef\xbb\xbf\xef\xbb\xbfa: 1\n")
            with self.assertRaisesRegex(sizing.InputError, "U\\+FEFF"):
                sizing.load_documents(path, "bom")
            path.write_bytes(b'{"a": "x\xe2\x80\xa8"}')
            with self.assertRaisesRegex(sizing.InputError, "U\\+2028"):
                sizing.load_documents(path, "json")

    def test_aliases_cannot_expand_without_bound(self):
        # Each level doubles the expanded size: 2**40 nodes in under 2 KB.
        text = "a0: &a0 [x, x]\n" + "".join(f"a{n}: &a{n}\n  - *a{n - 1}\n  - *a{n - 1}\n" for n in range(1, 41))
        self.assertLess(len(text), 2048)
        with self.assertRaisesRegex(sizing.InputError, "expands to more than"):
            parse(text)
        self.assertEqual(parse("a0: &a0 [x, x]\na1:\n  - *a0\n  - *a0\n")[0]["a1"], [["x", "x"], ["x", "x"]])

    def test_json_input_is_read_and_duplicate_keys_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            good, bad = Path(temp) / "good.json", Path(temp) / "bad.json"
            good.write_text('{"services": {"a": {"image": "x"}}}', encoding="utf-8")
            bad.write_text('{"services": {}, "services": {}}', encoding="utf-8")
            self.assertEqual(sizing.load_documents(good, "good"), [{"services": {"a": {"image": "x"}}}])
            with self.assertRaisesRegex(sizing.InputError, "duplicate JSON key"):
                sizing.load_documents(bad, "bad")
            with mock.patch.object(sizing, "MAX_INPUT_BYTES", 8):
                with self.assertRaisesRegex(sizing.InputError, "input limit"):
                    sizing.load_documents(good, "good")

    def test_the_shipped_compose_example_reads_with_its_anchors_resolved(self):
        document, = sizing.load_documents(ROOT / COMPOSE_EXAMPLE, COMPOSE_EXAMPLE)
        services = document["services"]
        self.assertEqual(services["gateway-1"]["environment"], services["gateway-2"]["environment"])
        self.assertEqual(services["gateway-1"]["environment"]["DATABASE_POOL_MAX"], "10")
        self.assertEqual(services["gateway-1"]["environment"]["STATE_BACKEND"], "postgres")
        self.assertIn("max_connections=100", services["db"]["command"])
        self.assertIn("upstream greengateway {\n", document["configs"]["nginx-conf"]["content"])
        self.assertEqual(services["migrate"]["command"], ["migrate", "up"])


class ArithmeticTests(unittest.TestCase):
    def test_exact_fit_passes_and_one_more_connection_is_rejected(self):
        # 100 - 3 - 2 = 95 available; headroom 2 + 2 + 4 + 1 + 1 + 2 + 0 = 12.
        server = ["--max-connections", "100", "--superuser-reserved-connections", "3",
                  "--reserved-connections", "2"]
        code, result = decision("--replicas", "1", "--surge", "0", "--pool-max", "83", *server, *DIRECT)
        self.assertEqual((code, result["status"], result["total"], result["spare"]), (0, "fits", 95, 0))
        code, result = decision("--replicas", "1", "--surge", "0", "--pool-max", "84", *server, *DIRECT)
        self.assertEqual((code, result["status"], result["total"]), (1, "rejected", 96))
        self.assertIn("over by 1", result["problems"][-1])

    def test_reserved_connections_are_taken_from_the_budget(self):
        args = ["--replicas", "1", "--surge", "0", "--pool-max", "83", "--max-connections", "100",
                "--superuser-reserved-connections", "3"]
        self.assertEqual(decision(*args, "--reserved-connections", "2", *DIRECT)[0], 0)
        code, result = decision(*args, "--reserved-connections", "3", *DIRECT)
        self.assertEqual((code, result["available"]), (1, 94))

    def test_reserved_slots_must_leave_ordinary_connections(self):
        code, _, err = run("check", "--replicas", "1", "--surge", "0", "--max-connections", "10",
                           "--superuser-reserved-connections", "7", "--reserved-connections", "3", *DIRECT)
        self.assertEqual(code, 2)
        self.assertIn("PostgreSQL refuses to start", err)

    def test_autoscaler_maximum_and_rollout_surge_set_the_ceiling(self):
        _, result = decision("--replicas", "2", "--autoscaler-max", "6", "--surge", "0", *SERVER, *DIRECT)
        self.assertEqual((result["pods"], result["pool_connections"]), (6, 60))
        _, result = decision("--replicas", "8", "--autoscaler-max", "6", "--surge", "0", *SERVER, *DIRECT)
        self.assertEqual(result["pods"], 8)
        _, result = decision("--replicas", "6", "--autoscaler-max", "6", "--surge", "2", *SERVER, *DIRECT)
        self.assertEqual((result["pods"], result["pool_connections"]), (8, 80))
        code, result = decision("--replicas", "2", "--autoscaler-max", "9", "--surge", "0", *SERVER, *DIRECT)
        self.assertEqual((code, result["total"]), (1, 102))

    def test_rejection_explains_the_headroom_and_what_would_fit(self):
        code, out, _ = run("check", "--replicas", "10", "--surge", "0", *SERVER, *DIRECT)
        self.assertEqual(code, 1)
        self.assertIn("REJECTED: 100 + 12 = 112 of 97 connections", out)
        self.assertIn("over by 15", out)
        self.assertIn("lower DATABASE_POOL_MAX to 8 on every serving replica (10 pods x 8 + 12 = 92)", out)
        self.assertIn("run at most 8 gateway pods at once", out)
        self.assertIn("raise max_connections to at least 115", out)
        for name in sizing.HEADROOM_NAMES:
            self.assertRegex(out, rf"\n  {name} +\d+  (default|declared): ")
        self.assertNotRegex(out.lower(), "unlimited|disable")

    def test_headroom_that_cannot_fit_any_pool_says_so(self):
        code, out, _ = run("check", "--replicas", "4", "--surge", "0", "--max-connections", "16",
                           "--superuser-reserved-connections", "3", "--reserved-connections", "0", *DIRECT)
        self.assertEqual(code, 1)
        self.assertIn("no DATABASE_POOL_MAX fits 4 pods: the headroom alone leaves 1 connection", out)
        self.assertNotIn("run at most", out)
        self.assertIn("raise max_connections to at least 55", out)

    def test_every_operator_headroom_entry_must_be_named(self):
        for name in ("backup", "monitoring", "operator", "other"):
            args = [arg for index, arg in enumerate(HEADROOM)
                    if HEADROOM[index - (index % 2)] != f"--{name}"]
            with self.subTest(name=name):
                code, _, err = run("check", "--replicas", "1", "--surge", "0", *SERVER, "--pooler", "none", *args)
                self.assertEqual(code, 2)
                self.assertIn(f"name the {name} headroom, even if it is 0", err)

    def test_declared_headroom_replaces_a_default_and_is_reported(self):
        _, result = decision("--replicas", "1", "--surge", "0", *SERVER, *DIRECT, "--import", "0")
        self.assertEqual(result["headroom"]["import"], {"value": 0, "origin": "declared"})
        self.assertEqual(result["headroom"]["migrator"], {"value": 2, "origin": "default"})

    def test_small_pools_carry_a_note_about_the_maintenance_leader(self):
        _, result = decision("--replicas", "2", "--surge", "0", "--pool-max", "2", *SERVER, *DIRECT)
        self.assertTrue(any("leaves the leader 1 for requests" in note for note in result["notes"]))

    def test_malformed_numbers_and_sources_are_refused(self):
        base = ["check", *SERVER, *DIRECT]
        cases = [
            (["--replicas", "+3", "--surge", "0"], "whole number written plainly"),
            (["--replicas", "1_0", "--surge", "0"], "whole number written plainly"),
            (["--replicas", " 3", "--surge", "0"], "whole number written plainly"),
            (["--replicas", "-1", "--surge", "0"], "expected one argument|whole number"),
            (["--replicas", "0", "--surge", "0"], "must be at least 1"),
            (["--replicas", "3"], "name the rollout surge"),
            (["--replicas", "3", "--surge", "0", "--pool-max", "0"], "between 1 and 256"),
            (["--replicas", "3", "--surge", "0", "--pool-max", "257"], "between 1 and 256"),
            (["--surge", "0"], "exactly one of"),
        ]
        for extra, message in cases:
            with self.subTest(extra=extra):
                code, _, err = run(*base, *extra)
                self.assertEqual(code, 2)
                self.assertRegex(err, message)

    def test_the_server_limits_must_be_named_by_hand_without_a_server_in_the_files(self):
        code, _, err = run("check", "--replicas", "1", "--surge", "0", "--max-connections", "100", *DIRECT)
        self.assertEqual(code, 2)
        self.assertIn("name the server's limits", err)

    def test_pool_sizes_match_the_gateway_configuration(self):
        config = (ROOT / "gateway/src/config.rs").read_text(encoding="utf-8")
        self.assertIn(f"pub const DEFAULT_DATABASE_POOL_MAX: usize = {sizing.DEFAULT_POOL_MAX};", config)
        self.assertIn(f"pub const MAX_DATABASE_POOL_MAX: usize = {sizing.MAX_POOL_MAX};", config)

    def test_every_cluster_one_shot_command_has_a_connection_cost(self):
        bootstrap = (ROOT / "gateway/src/bootstrap.rs").read_text(encoding="utf-8")
        words = set(re.findall(r'word == \*"([a-z-]+)"', bootstrap))
        self.assertTrue(words)
        self.assertEqual(words - set(sizing.COMMANDS), set())


class PoolerTests(unittest.TestCase):
    def test_a_session_pooler_is_budgeted_at_its_own_server_connections(self):
        args = ["--replicas", "4", "--surge", "0", *SERVER, *HEADROOM]
        code, result = decision(*args, "--pooler", "none")
        self.assertEqual((code, result["total"]), (0, 52))
        code, result = decision(*args, "--pooler", "session", "--pooler-server-connections", "60")
        self.assertEqual((code, result["server_side"], result["total"]), (0, 60, 72))
        code, result = decision(*args, "--pooler", "session", "--pooler-server-connections", "90")
        self.assertEqual((code, result["total"]), (1, 102))

    def test_a_session_pooler_smaller_than_the_pools_is_rejected(self):
        code, result = decision("--replicas", "4", "--surge", "0", *SERVER, *HEADROOM, "--pooler", "session",
                                "--pooler-server-connections", "30")
        self.assertEqual(code, 1)
        self.assertIn("the pooler can hold 30 server sessions but the gateway pools can ask for 40",
                      result["problems"][0])

    def test_transaction_and_statement_pooling_are_rejected_whatever_the_arithmetic(self):
        for mode in ("transaction", "statement"):
            with self.subTest(mode=mode):
                code, result = decision("--replicas", "1", "--surge", "0", *SERVER, *HEADROOM, "--pooler", mode)
                self.assertEqual((code, result["status"]), (1, "rejected"))
                self.assertLessEqual(result["total"], result["available"])
                self.assertIn("advisory locks", result["problems"][0])

    def test_pooler_server_connections_belong_to_a_session_pooler_only(self):
        for extra in (["--pooler", "session"], ["--pooler", "none", "--pooler-server-connections", "10"]):
            with self.subTest(extra=extra):
                code, _, err = run("check", "--replicas", "1", "--surge", "0", *SERVER, *HEADROOM, *extra)
                self.assertEqual(code, 2)
                self.assertIn("required with a session pooler", err)

    def test_an_unknown_pooler_mode_is_refused(self):
        code, _, err = run("check", "--replicas", "1", "--surge", "0", *SERVER, *HEADROOM, "--pooler", "magic")
        self.assertEqual(code, 2)
        self.assertIn("invalid choice", err)


COMPOSE = """\
x-env: &env
  STATE_BACKEND: postgres
  DATABASE_POOL_MAX: "10"
services:
  db:
    image: postgres:16
    command: [postgres, -c, max_connections=60, -c, superuser_reserved_connections=2]
  gateway:
    image: gateway
    environment: *env
  migrate:
    image: gateway
    environment: *env
    command: [migrate, up]
  lb:
    image: nginx
"""


CONFIRMED = ["--server-service", "db"]


class ComposeTests(Files):
    def compose(self, text, *extra, flags=DIRECT, server=CONFIRMED):
        return decision("--compose", self.write("compose.yml", text), *server, *flags, *extra)

    def compose_invalid(self, text, message, *extra, server=CONFIRMED):
        self.assertInvalid(["check", "--compose", self.write("compose.yml", text), *server, *DIRECT, *extra],
                           message)

    def test_the_shipped_example_reads_as_two_pools_two_jobs_and_its_own_server(self):
        document, = sizing.load_documents(ROOT / COMPOSE_EXAMPLE, COMPOSE_EXAMPLE)
        facts = sizing.compose_facts(document, COMPOSE_EXAMPLE)
        self.assertEqual([(pool["name"], pool["replicas"], pool["pool_max"]) for pool in facts["pools"]],
                         [("service gateway-1", 1, 10), ("service gateway-2", 1, 10)])
        self.assertEqual(sorted(job["command"] for job in facts["jobs"]), ["import-standalone", "migrate"])
        self.assertEqual(list(facts["servers"]), ["db"])
        limits = sizing.compose_server_limits("db", facts["servers"]["db"], "db")
        self.assertEqual(limits["max_connections"], (100, "service db command"))
        self.assertEqual(limits["superuser_reserved_connections"][0], 3)
        self.assertIn("PostgreSQL default", limits["superuser_reserved_connections"][1])
        self.assertEqual(sorted(facts["uncounted"]), ["db-bootstrap", "db-grants", "lb"])

    def test_server_limits_come_from_the_confirmed_database_service_command(self):
        code, result = self.compose(COMPOSE)
        self.assertEqual(code, 0)
        self.assertEqual(result["available"], 58)
        self.assertEqual(result["server_service"], "db")
        self.assertEqual(result["server"]["superuser_reserved_connections"]["origin"], "service db command")
        self.assertIn("not on the service's command line", result["server"]["reserved_connections"]["origin"])
        self.assertTrue(any("SHOW it on the running server" in note for note in result["notes"]))
        self.assertEqual(result["uncounted"], ["lb"])
        self.assertEqual(result["required"], {"migrator": 2})

    def test_a_postgres_service_is_never_assumed_to_be_the_gateways_server(self):
        # The gateways' DSN is a secret file, so a PostgreSQL service beside
        # them may be some other application's database.
        self.compose_invalid(COMPOSE, r"runs PostgreSQL \(db\).*--server-service NAME", server=())

    def test_declared_server_limits_are_authoritative_and_the_files_postgres_is_ignored(self):
        # An identity provider's database beside four gateways that use a
        # managed server with max_connections=40: 40 + 12 = 52 of 37.
        text = ("x-env: &env\n  STATE_BACKEND: postgres\nservices:\n  keycloak-db:\n    image: postgres:16\n"
                "  gateway:\n    image: gateway\n    scale: 4\n    environment: *env\n")
        flags = ["--max-connections", "40", "--superuser-reserved-connections", "3", "--reserved-connections", "0"]
        self.compose_invalid(text, r"runs PostgreSQL \(keycloak-db\)", server=())
        code, result = self.compose(text, server=flags)
        self.assertEqual((code, result["status"], result["total"], result["available"]), (1, "rejected", 52, 37))
        self.assertEqual((result["server_service"], result["ignored_servers"]), (None, ["keycloak-db"]))
        self.assertEqual(result["server"]["max_connections"], {"value": 40, "origin": "declared"})
        code, out, _ = run("check", "--compose", self.write("compose.yml", text), *flags, *DIRECT)
        self.assertEqual(code, 1)
        self.assertIn("ignored, runs PostgreSQL that is not the gateways' server: keycloak-db", out)
        # The ignored server's own settings are not read, so they cannot refuse the check.
        broken = text.replace("    image: postgres:16\n", "    image: postgres:16\n"
                              "    command: [postgres, -c, config_file=/etc/pg.conf]\n")
        self.assertEqual(self.compose(broken, server=flags)[0], 1)

    def test_the_server_service_must_be_a_postgres_service_and_excludes_declared_limits(self):
        self.compose_invalid(COMPOSE, "name either the server service or the server's limits, not both",
                             server=CONFIRMED + SERVER)
        self.compose_invalid(COMPOSE, "service lb is named as the gateways' PostgreSQL server.*runs PostgreSQL as db",
                             server=["--server-service", "lb"])
        self.compose_invalid(COMPOSE, "service nope is named", server=["--server-service", "nope"])
        self.assertInvalid(["check", "--replicas", "1", "--surge", "0", "--server-service", "db", *SERVER, *DIRECT],
                           "names a service of a Compose file")

    def test_postgres_command_line_forms(self):
        cases = [
            ("[postgres, -N, '40']", 40), ("[postgres, -N40]", 40), ("[postgres, -cmax_connections=41]", 41),
            ("[postgres, --max-connections=42]", 42), ("[-c, max_connections=43]", 43), ("[]", 100),
        ]
        for command, expected in cases:
            with self.subTest(command=command):
                text = COMPOSE.replace("[postgres, -c, max_connections=60, -c, superuser_reserved_connections=2]",
                                       command)
                _, result = self.compose(text)
                self.assertEqual(result["server"]["max_connections"]["value"], expected)

    def test_unreadable_or_ambiguous_server_settings_are_refused(self):
        cases = [
            ("[postgres, -c, max_connections=60, -c, max_connections=70]", "sets max_connections twice"),
            ("[postgres, -c, config_file=/etc/pg.conf]", "file the guard cannot see"),
            ("[postgres, -c, max_connections=1e2]", "whole number"),
        ]
        for command, message in cases:
            with self.subTest(command=command):
                text = COMPOSE.replace("[postgres, -c, max_connections=60, -c, superuser_reserved_connections=2]",
                                       command)
                self.compose_invalid(text, message)
        two = COMPOSE + "  db2:\n    image: postgres:16\n"
        self.compose_invalid(two, r"runs PostgreSQL \(db, db2\)", server=())
        code, result = self.compose(two)
        self.assertEqual((code, result["server_service"], result["ignored_servers"]), (0, "db", ["db2"]))

    def test_replicas_scale_and_start_first_surge(self):
        gateway = "  gateway:\n    image: gateway\n    environment: *env\n"
        cases = [
            ("    scale: 3\n", 3, 0),
            ("    deploy:\n      replicas: 3\n", 3, 0),
            ("    deploy:\n      replicas: 3\n      update_config:\n        order: start-first\n", 3, 1),
            ("    deploy:\n      replicas: 3\n      update_config:\n        order: start-first\n"
             "        parallelism: 0\n", 3, 3),
        ]
        for extra, replicas, surge in cases:
            with self.subTest(extra=extra):
                _, result = self.compose(COMPOSE.replace(gateway, gateway + extra))
                pool = result["pools"][0]
                self.assertEqual((pool["replicas"], pool["surge"]), (replicas, surge))
        for extra, message in [("    scale: 2\n    deploy:\n      replicas: 3\n", "different values"),
                               ("    deploy:\n      mode: global\n", "deploy.mode"),
                               ("    scale: two\n", "whole number")]:
            with self.subTest(extra=extra):
                self.compose_invalid(COMPOSE.replace(gateway, gateway + extra), message)

    def test_line_breaks_yaml_tools_disagree_about_are_refused(self):
        # Compose reads a lone CR, NEL, LS or PS as a line break, so this is a
        # cluster-mode gateway at pool 50 to it; it must not read as an image.
        for char in ("\r", "\x85", "\u2028", "\u2029"):
            with self.subTest(char=repr(char)):
                gateway = char.join(["    image: gateway", "    environment:", "      - STATE_BACKEND=postgres",
                                     "      - DATABASE_POOL_MAX=50\n"])
                text = ("services:\n  db:\n    image: postgres:16\n    command: [postgres, -c, max_connections=20]\n"
                        "  gw:\n" + gateway)
                self.compose_invalid(text, r"compose\.yml:6: contains")

    def test_a_flow_mapping_key_with_a_colon_is_not_a_sizing_variable(self):
        # To Compose this is `DATABASE_POOL_MAX:5` with no value, so the four
        # gateways run at the default pool of 10, not at 5.
        text = ("services:\n  db:\n    image: postgres:16\n    command: [postgres, -c, max_connections=40]\n"
                "  gateway:\n    image: gateway\n    scale: 4\n"
                "    environment: {STATE_BACKEND: postgres, DATABASE_POOL_MAX:5}\n")
        self.compose_invalid(text, r"compose\.yml:8: expected ':' in a flow mapping")
        _, result = self.compose(text.replace("DATABASE_POOL_MAX:5", "DATABASE_POOL_MAX: 5"))
        self.assertEqual(result["pools"][0]["pool_max"], 5)

    def test_environment_list_form_and_trimmed_backend(self):
        text = COMPOSE.replace("    environment: *env\n  migrate", "    environment:\n"
                               "      - STATE_BACKEND= postgres \n      - DATABASE_POOL_MAX=7\n  migrate", 1)
        _, result = self.compose(text)
        self.assertEqual(result["pools"][0]["pool_max"], 7)

    def test_unresolvable_or_malformed_sizing_values_are_refused(self):
        cases = [
            ('DATABASE_POOL_MAX: "${POOL:-10}"', "interpolated by Compose"),
            ("DATABASE_POOL_MAX:", "shell that runs Compose"),
            ('DATABASE_POOL_MAX: ""', "between 1 and 256"),
            ('DATABASE_POOL_MAX: "abc"', "between 1 and 256"),
            ('DATABASE_POOL_MAX: "0"', "between 1 and 256"),
            ('DATABASE_POOL_MAX: "257"', "between 1 and 256"),
            ('DATABASE_POOL_MAX: "+10"', "between 1 and 256"),
            ('DATABASE_POOL_MAX: " 10"', "between 1 and 256"),
            # Compose reads a plain 010 as octal 8; the gateway would read "010" as 10.
            ("DATABASE_POOL_MAX: 010", "leading zero"),
        ]
        for line, message in cases:
            with self.subTest(line=line):
                self.compose_invalid(COMPOSE.replace('DATABASE_POOL_MAX: "10"', line), message)
        for value in ("postgresql", '""', "${MODE}"):
            with self.subTest(value=value):
                self.compose_invalid(COMPOSE.replace("STATE_BACKEND: postgres", f"STATE_BACKEND: {value}"),
                                     "STATE_BACKEND")

    def test_files_the_guard_cannot_see_through_are_refused(self):
        cases = [
            ("    env_file: gateway.env\n", "uses env_file"),
            ("    extends: {service: base}\n", "uses extends"),
            ("    entrypoint: [/bin/sh, -c]\n", "replaces the gateway's entrypoint"),
            ("    command: [serve-fast]\n", "does not know how many connections"),
        ]
        for extra, message in cases:
            with self.subTest(extra=extra):
                self.compose_invalid(COMPOSE.replace("    environment: *env\n  migrate", "    environment: *env\n"
                                                     + extra + "  migrate", 1), message)
        self.compose_invalid("include:\n  - other.yml\n" + COMPOSE, "includes other Compose files")

    def test_a_default_named_file_with_an_override_beside_it_is_refused(self):
        # Compose run without -f merges the override file over compose.yaml.
        for name, override in [("compose.yaml", "compose.override.yaml"),
                               ("docker-compose.yml", "docker-compose.override.yml")]:
            with self.subTest(name=name):
                path = self.write(name, COMPOSE)
                self.assertEqual(decision("--compose", path, *CONFIRMED, *DIRECT)[0], 0)
                self.write(override, "services:\n  gateway:\n    scale: 9\n")
                self.assertInvalid(["check", "--compose", path, *CONFIRMED, *DIRECT], f"merges {override} over")
                (self.root / override).unlink()
        # A file Compose reads only through -f takes no override.
        self.write("docker-compose.override.yml", "services: {}\n")
        self.assertEqual(decision("--compose", self.write("docker-compose.ha.yml", COMPOSE), *CONFIRMED, *DIRECT)[0],
                         0)

    def test_the_gateway_entrypoint_may_be_named_explicitly(self):
        text = COMPOSE.replace("    command: [migrate, up]", "    entrypoint: [/usr/local/bin/gateway, migrate, up]")
        _, result = self.compose(text)
        self.assertEqual([job["command"] for job in result["jobs"]], ["migrate"])

    def test_a_deployments_own_jobs_need_their_headroom(self):
        code, result = self.compose(COMPOSE, "--migrator", "1")
        self.assertEqual(code, 1)
        self.assertIn("the migrator headroom is 1", result["problems"][0])
        doubled = COMPOSE.replace("    command: [migrate, up]\n", "    command: [migrate, up]\n    scale: 2\n")
        code, result = self.compose(doubled)
        self.assertEqual(code, 1)
        self.assertIn("can hold 4 connections at once", result["problems"][0])

    def test_rendered_compose_json_is_accepted(self):
        document, = sizing.load_documents(ROOT / COMPOSE_EXAMPLE, COMPOSE_EXAMPLE)
        _, direct = decision("--compose", str(ROOT / COMPOSE_EXAMPLE), *CONFIRMED, *DIRECT)
        rendered = self.write("rendered.json", json.dumps(document))
        code, result = decision("--compose", rendered, *CONFIRMED, *DIRECT)
        self.assertEqual((code, result["total"]), (0, direct["total"]))


DEPLOYMENT = """\
apiVersion: v1
kind: ConfigMap
metadata:
  name: gateway
data:
  STATE_BACKEND: postgres
  DATABASE_POOL_MAX: "10"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gateway
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: gateway
          image: gateway
          envFrom:
            - configMapRef:
                name: gateway
"""
HPA = """\
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: gateway
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: gateway
  minReplicas: 2
  maxReplicas: 6
"""


class KubernetesTests(Files):
    def kubernetes(self, text, *extra):
        return decision("--kubernetes", self.write("manifests.yaml", text), *SERVER, *DIRECT, *extra)

    def invalid(self, text, message, *extra):
        self.assertInvalid(["check", "--kubernetes", self.write("manifests.yaml", text), *SERVER, *DIRECT,
                            *extra], message)

    def test_deployment_default_surge_rounds_up(self):
        _, result = self.kubernetes(DEPLOYMENT)
        pool = result["pools"][0]
        self.assertEqual((pool["replicas"], pool["autoscaler_max"], pool["surge"]), (3, None, 1))
        self.assertEqual(result["pool_connections"], 40)

    def test_the_autoscaler_maximum_is_the_replica_ceiling(self):
        code, result = self.kubernetes(DEPLOYMENT + HPA)
        pool = result["pools"][0]
        self.assertEqual((pool["autoscaler_max"], pool["surge"], result["pods"]), (6, 2, 8))
        self.assertEqual((code, result["total"]), (0, 92))
        code, result = self.kubernetes(DEPLOYMENT + HPA.replace("maxReplicas: 6", "maxReplicas: 7"))
        self.assertEqual((code, result["pods"], result["total"]), (1, 9, 102))

    def test_an_autoscaler_without_a_namespace_may_scale_a_namespaced_deployment(self):
        namespaced = DEPLOYMENT.replace("metadata:\n  name: gateway\nspec:", "metadata:\n  name: gateway\n"
                                        "  namespace: prod\nspec:").replace(
            "metadata:\n  name: gateway\ndata:", "metadata:\n  name: gateway\n  namespace: prod\ndata:")
        _, result = self.kubernetes(namespaced + HPA)
        self.assertEqual(result["pools"][0]["autoscaler_max"], 6)
        _, result = self.kubernetes(namespaced + HPA.replace("  name: gateway\nspec", "  name: gateway\n"
                                                             "  namespace: staging\nspec"))
        self.assertIsNone(result["pools"][0]["autoscaler_max"])

    def test_rollout_strategies(self):
        cases = [
            ("  strategy:\n    type: Recreate\n", 0),
            ("  strategy:\n    rollingUpdate:\n      maxSurge: 2\n", 2),
            ("  strategy:\n    rollingUpdate:\n      maxSurge: 50%\n", 2),
            ("  strategy:\n    rollingUpdate:\n      maxSurge: 0\n", 0),
        ]
        for strategy, surge in cases:
            with self.subTest(strategy=strategy):
                _, result = self.kubernetes(DEPLOYMENT.replace("  replicas: 3\n", "  replicas: 3\n" + strategy))
                self.assertEqual(result["pools"][0]["surge"], surge)
        _, result = self.kubernetes(DEPLOYMENT.replace("kind: Deployment", "kind: StatefulSet"))
        self.assertEqual(result["pools"][0]["surge"], 0)
        for strategy, message in [("  strategy:\n    rollingUpdate:\n      maxSurge: lots\n", "maxSurge"),
                                  ("  strategy:\n    type: BlueGreen\n", "unknown rollout strategy")]:
            with self.subTest(strategy=strategy):
                self.invalid(DEPLOYMENT.replace("  replicas: 3\n", "  replicas: 3\n" + strategy), message)

    def test_autoscalers_the_guard_cannot_read_are_refused(self):
        self.invalid(DEPLOYMENT + HPA.replace("minReplicas: 2", "minReplicas: 8"), "exceeds maxReplicas")
        self.invalid(DEPLOYMENT + HPA + HPA.replace("name: gateway\nspec", "name: second\nspec"), "scaled by both")
        keda = HPA.replace("autoscaling/v2", "keda.sh/v1alpha1").replace("HorizontalPodAutoscaler", "ScaledObject")
        self.invalid(DEPLOYMENT + keda, "reads only HorizontalPodAutoscaler")
        self.invalid(DEPLOYMENT + HPA.replace("  maxReplicas: 6\n", ""), "maxReplicas must be a whole number")

    def test_environment_sources_and_precedence(self):
        secret = ("---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: extra\ndata:\n  APP_DATABASE_POOL_MAX: "
                  + base64.b64encode(b"4").decode() + "\n")
        text = DEPLOYMENT.replace("                name: gateway\n", "                name: gateway\n"
                                  "            - secretRef:\n                name: extra\n              prefix: APP_\n")
        _, result = self.kubernetes(text + secret)
        self.assertEqual(result["pools"][0]["pool_max"], 10)
        text = text.replace("APP_", "")
        _, result = self.kubernetes(text + secret.replace("APP_", ""))
        self.assertEqual(result["pools"][0]["pool_max"], 4)
        explicit = DEPLOYMENT + "          env:\n            - name: DATABASE_POOL_MAX\n              value: \"5\"\n"
        _, result = self.kubernetes(explicit)
        self.assertEqual(result["pools"][0]["pool_max"], 5)
        by_key = DEPLOYMENT + ("          env:\n            - name: DATABASE_POOL_MAX\n              valueFrom:\n"
                               "                configMapKeyRef:\n                  name: gateway\n"
                               "                  key: DATABASE_POOL_MAX\n")
        _, result = self.kubernetes(by_key)
        self.assertEqual(result["pools"][0]["pool_max"], 10)

    def test_unresolved_environment_is_refused_unless_declared_external(self):
        external = DEPLOYMENT.replace("                name: gateway\n", "                name: gateway\n"
                                      "            - secretRef:\n                name: vault\n")
        self.invalid(external, "pass --external-env secret/vault")
        code, result = self.kubernetes(external, "--external-env", "secret/vault")
        self.assertEqual((code, result["external"]), (0, ["secret/vault"]))
        field = DEPLOYMENT + ("          env:\n            - name: DATABASE_POOL_MAX\n              valueFrom:\n"
                              "                fieldRef:\n                  fieldPath: metadata.name\n")
        self.invalid(field, "DATABASE_POOL_MAX is not a value")
        expanded = DEPLOYMENT + "          env:\n            - name: DATABASE_POOL_MAX\n              value: $(N)\n"
        self.invalid(expanded, r"\$\(\.\.\.\) expansion")
        broken = ("---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: extra\ndata:\n"
                  "  STATE_BACKEND: '!!!'\n")
        self.invalid(DEPLOYMENT.replace("configMapRef", "secretRef").replace("                name: gateway\n",
                                                                             "                name: extra\n")
                     + broken, "not base64")

    def test_one_shot_jobs_are_budgeted_as_headroom(self):
        job = ("---\napiVersion: batch/v1\nkind: Job\nmetadata:\n  name: migrate\nspec:\n  parallelism: 2\n"
               "  template:\n    spec:\n      containers:\n        - name: migrate\n          args: [migrate, up]\n"
               "          envFrom:\n            - configMapRef:\n                name: gateway\n")
        code, result = self.kubernetes(DEPLOYMENT + job)
        self.assertEqual((code, result["required"]), (1, {"migrator": 4}))
        code, result = self.kubernetes(DEPLOYMENT + job, "--migrator", "4")
        self.assertEqual(code, 0)
        cron = ("---\napiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: maintenance\nspec:\n"
                "  schedule: '*/5 * * * *'\n  jobTemplate:\n    spec:\n      template:\n        spec:\n"
                "          containers:\n            - name: run\n"
                "              command: [/usr/local/bin/gateway, maintenance-run]\n"
                "              envFrom:\n                - configMapRef:\n                    name: gateway\n")
        self.invalid(DEPLOYMENT + cron, "concurrencyPolicy: Forbid")
        code, result = self.kubernetes(DEPLOYMENT + cron.replace("  schedule:", "  concurrencyPolicy: Forbid\n"
                                                                  "  schedule:"))
        self.assertEqual((code, result["required"]), (0, {"maintenance": 3}))

    def test_workloads_the_guard_cannot_bound_are_refused(self):
        self.invalid(DEPLOYMENT.replace("kind: Deployment", "kind: DaemonSet"), "no replica count")
        rollout = DEPLOYMENT.replace("apiVersion: apps/v1\nkind: Deployment", "apiVersion: argoproj.io/v1alpha1\n"
                                     "kind: Rollout")
        self.invalid(rollout, "cannot bound a Rollout's replicas")
        code, result = self.kubernetes(rollout.replace("  STATE_BACKEND: postgres\n", ""))
        self.assertEqual((code, result["pools"]), (0, []))
        self.invalid(DEPLOYMENT + "          args: [migrate, up]\n", "restarts `migrate` for ever")
        self.invalid(DEPLOYMENT + "          command: [/bin/sh]\n", "replaces the gateway's entrypoint")
        self.invalid(DEPLOYMENT + DEPLOYMENT.split("---\n")[1].join(["---\n", ""]), "also defined in")
        self.invalid("apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nmetadata:\n  name: k\n",
                     "render it with `kubectl kustomize`")

    def test_unmodelled_kinds_that_run_a_gateway_workload_by_reference_are_refused(self):
        scaled_to_zero = DEPLOYMENT.replace("  replicas: 3\n", "  replicas: 0\n")
        rollout = ("---\napiVersion: argoproj.io/v1alpha1\nkind: Rollout\nmetadata:\n  name: gateway\nspec:\n"
                   "  replicas: 20\n  workloadRef:\n    apiVersion: apps/v1\n    kind: Deployment\n"
                   "    name: gateway\n    scaleDown: onsuccess\n")
        # Argo scales the Deployment to 0 and runs the Rollout's 20 pods.
        self.invalid(scaled_to_zero + rollout, "Rollout/gateway refers to .*Deployment/gateway, which runs the "
                     "gateway in cluster mode")
        canary = ("---\napiVersion: flagger.app/v1beta1\nkind: Canary\nmetadata:\n  name: gateway\nspec:\n"
                  "  targetRef:\n    apiVersion: apps/v1\n    kind: Deployment\n    name: gateway\n"
                  "  autoscalerRef:\n    apiVersion: autoscaling/v2\n    kind: HorizontalPodAutoscaler\n"
                  "    name: gateway\n")
        self.invalid(DEPLOYMENT + canary, "Canary/gateway refers to")
        vpa = ("---\napiVersion: autoscaling.k8s.io/v1\nkind: VerticalPodAutoscaler\nmetadata:\n  name: gateway\n"
               "spec:\n  targetRef:\n    apiVersion: apps/v1\n    kind: Deployment\n    name: gateway\n")
        self.invalid(DEPLOYMENT + vpa, "VerticalPodAutoscaler/gateway refers to")
        # A StatefulSet is matched too, and a missing namespace may be any namespace.
        self.invalid(DEPLOYMENT.replace("kind: Deployment", "kind: StatefulSet").replace(
            "metadata:\n  name: gateway\nspec:", "metadata:\n  name: gateway\n  namespace: prod\nspec:")
            .replace("metadata:\n  name: gateway\ndata:", "metadata:\n  name: gateway\n  namespace: prod\ndata:")
            + rollout.replace("kind: Deployment", "kind: StatefulSet"), "refers to")
        # A reference to a standalone workload, or to one in another namespace, runs no pool.
        code, result = self.kubernetes(scaled_to_zero.replace("  STATE_BACKEND: postgres\n", "") + rollout)
        self.assertEqual((code, result["pools"]), (0, []))
        elsewhere = rollout.replace("  name: gateway\nspec:", "  name: gateway\n  namespace: other\nspec:")
        namespaced = DEPLOYMENT.replace("metadata:\n  name: gateway\nspec:",
                                        "metadata:\n  name: gateway\n  namespace: prod\nspec:").replace(
            "metadata:\n  name: gateway\ndata:", "metadata:\n  name: gateway\n  namespace: prod\ndata:")
        self.assertEqual(self.kubernetes(namespaced + elsewhere)[0], 0)
        # The HorizontalPodAutoscaler is modelled, so its reference is counted, not refused.
        self.assertEqual(self.kubernetes(DEPLOYMENT + HPA)[1]["pools"][0]["autoscaler_max"], 6)

    def test_a_scaler_that_leaves_out_the_target_kind_matches_any_workload(self):
        keda = ("---\napiVersion: keda.sh/v1alpha1\nkind: ScaledObject\nmetadata:\n  name: gateway\nspec:\n"
                "  scaleTargetRef:\n    name: gateway\n  maxReplicaCount: 50\n")
        self.invalid(DEPLOYMENT + keda, "reads only HorizontalPodAutoscaler")

    def test_unmodelled_kinds_that_embed_a_cluster_mode_container_anywhere_are_refused(self):
        template = ("apiVersion: template.openshift.io/v1\nkind: Template\nmetadata:\n  name: gateway\nobjects:\n"
                    "  - apiVersion: apps/v1\n    kind: Deployment\n    metadata:\n      name: gateway\n"
                    "    spec:\n      template:\n        spec:\n          containers:\n            - name: gateway\n"
                    "              image: gateway\n              env:\n                - name: STATE_BACKEND\n"
                    "                  value: postgres\n")
        self.invalid(template, "Template/gateway container gateway runs the gateway in cluster mode")
        workflow = ("apiVersion: argoproj.io/v1alpha1\nkind: Workflow\nmetadata:\n  name: w\nspec:\n  templates:\n"
                    "    - name: serve\n      container:\n        image: gateway\n        env:\n"
                    "          - name: STATE_BACKEND\n            value: postgres\n")
        self.invalid(workflow, "Workflow/w container None runs the gateway in cluster mode")
        self.assertEqual(self.kubernetes(workflow.replace("value: postgres", "value: sqlite"))[0], 0)

    def test_any_object_with_items_is_a_list(self):
        configmap, deployment = (part for part in DEPLOYMENT.split("---\n"))
        items = [sizing._Yaml(configmap, "c").documents()[0], sizing._Yaml(deployment, "d").documents()[0]]
        listed = self.write("list.json", json.dumps({"apiVersion": "apps/v1", "kind": "DeploymentList",
                                                     "metadata": {"name": "x"}, "items": [
                                                         {"kind": "List", "items": items}]}))
        code, result = decision("--kubernetes", listed, *SERVER, *DIRECT)
        self.assertEqual((code, result["pool_connections"]), (0, 40))

    def test_reports_with_pools_note_pods_that_are_still_draining(self):
        _, result = self.kubernetes(DEPLOYMENT)
        self.assertTrue(any("shutting down keeps its pool" in note for note in result["notes"]))
        _, result = self.kubernetes(DEPLOYMENT.replace("  STATE_BACKEND: postgres\n", ""))
        self.assertFalse(any("shutting down" in note for note in result["notes"]))

    def test_standalone_workloads_open_no_pool(self):
        code, result = self.kubernetes(DEPLOYMENT.replace("  STATE_BACKEND: postgres\n", ""))
        self.assertEqual((code, result["pools"], result["uncounted"]), (0, [], ["Deployment/gateway"]))

    def test_list_documents_are_expanded(self):
        configmap, deployment = (part for part in DEPLOYMENT.split("---\n"))
        items = [sizing._Yaml(configmap, "c").documents()[0], sizing._Yaml(deployment, "d").documents()[0]]
        listed = self.write("list.json", json.dumps({"apiVersion": "v1", "kind": "List", "items": items}))
        code, result = decision("--kubernetes", listed, *SERVER, *DIRECT)
        self.assertEqual((code, result["pool_connections"]), (0, 40))

    def test_line_breaks_yaml_tools_disagree_about_are_refused(self):
        # kubectl reads the ConfigMap below as setting STATE_BACKEND=postgres.
        for char in ("\r", "\x85", "\u2028", "\u2029"):
            with self.subTest(char=repr(char)):
                text = DEPLOYMENT.replace("  STATE_BACKEND: postgres\n", "  LOG: info" + char + "  STATE_BACKEND: "
                                          "postgres\n")
                self.invalid(text, r"manifests\.yaml:6: contains")

    def test_external_env_belongs_to_kubernetes_input(self):
        self.assertInvalid(["check", "--replicas", "1", "--surge", "0", "--external-env", "secret/x", *SERVER,
                            *DIRECT], "Kubernetes manifests only")


class ExampleTests(Files):
    def setUp(self):
        super().setUp()
        shutil.copytree(ROOT / "deploy", self.root / "deploy")
        (self.root / "docs/deployment").mkdir(parents=True)
        shutil.copyfile(ROOT / COMPOSE_EXAMPLE, self.root / COMPOSE_EXAMPLE)

    def edit(self, name, old, new):
        path = self.root / name
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")

    def test_the_shipped_examples_fit(self):
        results = {result["source"]: result for result in sizing.examples(ROOT)}
        compose = results.pop(COMPOSE_EXAMPLE)
        self.assertEqual(compose["server_service"], "db")
        self.assertEqual(compose["status"], "fits")
        self.assertLessEqual(compose["total"], compose["available"])
        self.assertTrue(results)
        self.assertEqual({result["status"] for result in results.values()}, {"standalone"})
        self.assertEqual(run("examples")[0], 0)

    def test_an_example_that_over_commits_is_rejected(self):
        before = sizing.examples(self.root)[0]
        self.edit(COMPOSE_EXAMPLE, 'DATABASE_POOL_MAX: "10"', 'DATABASE_POOL_MAX: "256"')
        compose = sizing.examples(self.root)[0]
        self.assertEqual(compose["status"], "rejected")
        self.assertEqual(compose["pool_connections"], before["pods"] * 256)
        self.assertGreater(compose["total"], compose["available"])

    def test_an_added_replica_is_counted(self):
        before = sizing.examples(self.root)[0]
        self.edit(COMPOSE_EXAMPLE, "  gateway-2:\n    <<: *gateway-service\n",
                  "  gateway-2:\n    <<: *gateway-service\n    scale: 20\n")
        compose = sizing.examples(self.root)[0]
        self.assertEqual((compose["status"], compose["pods"]), ("rejected", before["pods"] + 19))

    def test_a_new_database_client_must_be_budgeted(self):
        self.edit(COMPOSE_EXAMPLE, "  gateway-1:\n", "  exporter:\n    image: exporter\n\n  gateway-1:\n")
        with self.assertRaisesRegex(sizing.InputError, "budget a new database client"):
            sizing.examples(self.root)

    def test_a_cluster_mode_kubernetes_example_needs_a_budget(self):
        self.edit("deploy/kubernetes/greengateway.example.yaml", '  LISTEN_ADDR: "0.0.0.0:8080"\n',
                  '  LISTEN_ADDR: "0.0.0.0:8080"\n  STATE_BACKEND: "postgres"\n')
        with self.assertRaisesRegex(sizing.InputError, "names no connection budget"):
            sizing.examples(self.root)
        budgets = {**sizing.EXAMPLE_BUDGETS, "deploy/kubernetes/greengateway.example.yaml": {
            "pooler": "none", "headroom": {"backup": 1, "monitoring": 1, "operator": 2, "other": 0},
            "uncounted": [], "server": {"max_connections": 20, "superuser_reserved_connections": 3,
                                        "reserved_connections": 0}}}
        with mock.patch.object(sizing, "EXAMPLE_BUDGETS", budgets):
            results = {result["source"]: result for result in sizing.examples(self.root)}
        kubernetes = results["deploy/kubernetes/greengateway.example.yaml"]
        # One replica plus a 25% surge of one pod, at the default pool of 10.
        self.assertEqual((kubernetes["status"], kubernetes["pool_connections"], kubernetes["total"]),
                         ("rejected", 20, 32))
        entry = budgets["deploy/kubernetes/greengateway.example.yaml"]
        for broken, message in [({k: v for k, v in entry.items() if k != "server"}, "exactly one of server"),
                                ({**entry, "server_service": "db"}, "exactly one of server"),
                                ({**entry, "headrooms": {}}, "needs pooler, headroom, uncounted"),
                                ({**entry, "server": {"max_connections": 20}}, "must name the server's"),
                                ({**{k: v for k, v in entry.items() if k != "server"}, "server_service": "db"},
                                 "this is not a Compose file"),
                                ({**entry, "headroom": {**entry["headroom"], "backup": "one"}}, "whole number")]:
            with self.subTest(broken=broken):
                with mock.patch.object(sizing, "EXAMPLE_BUDGETS", {
                        **budgets, "deploy/kubernetes/greengateway.example.yaml": broken}):
                    with self.assertRaisesRegex(sizing.InputError, message):
                        sizing.examples(self.root)

    def test_a_stale_budget_is_refused(self):
        budgets = {**sizing.EXAMPLE_BUDGETS, "docs/deployment/gone.yml": {}}
        with mock.patch.object(sizing, "EXAMPLE_BUDGETS", budgets):
            with self.assertRaisesRegex(sizing.InputError, "no shipped example runs in cluster mode"):
                sizing.examples(self.root)

    def test_kustomize_overlays_cannot_move_sizing_inputs(self):
        self.edit("deploy/kubernetes-management/kustomization.yaml", "patches:", "replicas:\n  - name: x\n"
                  "    count: 9\npatches:")
        with self.assertRaisesRegex(sizing.InputError, "can change sizing inputs"):
            sizing.examples(self.root)

    def test_kustomize_patches_cannot_touch_sizing_inputs(self):
        for old, new in [("spec:\n  template:", "spec:\n  replicas: 9\n  template:"),
                         ('              value: "0.0.0.0:9090"\n',
                          '              value: "0.0.0.0:9090"\n            - name: DATABASE_POOL_MAX\n'
                          '              value: "99"\n')]:
            with self.subTest(new=new):
                shutil.copyfile(ROOT / "deploy/kubernetes-management/patch.yaml",
                                self.root / "deploy/kubernetes-management/patch.yaml")
                self.edit("deploy/kubernetes-management/patch.yaml", old, new)
                with self.assertRaisesRegex(sizing.InputError, "patches a sizing input"):
                    sizing.examples(self.root)

    def test_kustomize_resources_must_be_shipped_examples(self):
        self.edit("deploy/kubernetes/kustomization.yaml", "  - network-policy.example.yaml\n",
                  "  - network-policy.example.yaml\n  - https://example.test/remote.yaml\n")
        with self.assertRaisesRegex(sizing.InputError, "not a shipped example"):
            sizing.examples(self.root)

    def test_the_rendered_compose_output_must_agree_with_the_guards_reading(self):
        document, = sizing.load_documents(self.root / COMPOSE_EXAMPLE, COMPOSE_EXAMPLE)
        services = dict(reversed(list(document["services"].items())))
        agreeing = self.write("agreeing.json", json.dumps({**document, "services": services}))
        sizing.examples(self.root, {COMPOSE_EXAMPLE: agreeing})
        services["gateway-1"] = {**services["gateway-1"], "environment": {
            **services["gateway-1"]["environment"], "DATABASE_POOL_MAX": "11"}}
        differing = self.write("differing.json", json.dumps({**document, "services": services}))
        with self.assertRaisesRegex(sizing.InputError, "reads pools differently from Compose's rendering"):
            sizing.examples(self.root, {COMPOSE_EXAMPLE: differing})
        with self.assertRaisesRegex(sizing.InputError, "not a Compose example in docs/deployment"):
            sizing.examples(self.root, {"docker-compose.yml": agreeing})

    def test_the_example_budget_names_the_server_its_gateways_use(self):
        budget = sizing.EXAMPLE_BUDGETS[COMPOSE_EXAMPLE]
        self.assertEqual(budget["server_service"], "db")
        compose = sizing.examples(self.root)[0]
        self.assertEqual((compose["server_service"], compose["ignored_servers"]), ("db", []))
        for broken, message in [({**budget, "server_service": "lb"}, "service lb is named"),
                                ({**budget, "server": dict(sizing.POSTGRES_DEFAULTS)}, "exactly one of server")]:
            with self.subTest(broken=broken):
                with mock.patch.object(sizing, "EXAMPLE_BUDGETS", {COMPOSE_EXAMPLE: broken}):
                    with self.assertRaisesRegex(sizing.InputError, message):
                        sizing.examples(self.root)
        # Limits in the budget instead: the file's own PostgreSQL is reported as ignored.
        declared = {k: v for k, v in budget.items() if k != "server_service"}
        declared["server"] = {"max_connections": 40, "superuser_reserved_connections": 3, "reserved_connections": 0}
        with mock.patch.object(sizing, "EXAMPLE_BUDGETS", {COMPOSE_EXAMPLE: declared}):
            compose = sizing.examples(self.root)[0]
        self.assertEqual((compose["status"], compose["available"], compose["ignored_servers"]),
                         ("fits", 37, ["db"]))

    def test_repository_root_compose_overlays_must_stay_standalone(self):
        self.write("docker-compose.yml", "services:\n  gateway:\n    image: gateway\n")
        self.write("docker-compose.load.yml", "services:\n  gateway:\n    environment:\n      X: '1'\n")
        results = {result["source"]: result for result in sizing.examples(self.root)}
        self.assertEqual(results["docker-compose.load.yml"]["status"], "standalone")
        self.write("docker-compose.load.yml", "services:\n  gateway:\n    environment:\n"
                   "      STATE_BACKEND: postgres\n")
        with self.assertRaisesRegex(sizing.InputError, "overlays combined with -f"):
            sizing.examples(self.root)
        self.write("docker-compose.load.yml", "services:\n  gateway:\n    env_file: gateway.env\n")
        with self.assertRaisesRegex(sizing.InputError, "uses env_file"):
            sizing.examples(self.root)

    def test_the_shipped_repository_root_compose_files_are_checked(self):
        sources = {result["source"] for result in sizing.examples(ROOT)}
        shipped = {path.name for pattern in ("docker-compose*.y*ml", "compose*.y*ml") for path in ROOT.glob(pattern)}
        self.assertTrue(shipped)
        self.assertLessEqual(shipped, sources)


class WorkflowTests(unittest.TestCase):
    def test_a_required_job_checks_the_shipped_examples_before_building(self):
        # Read as text, so the workflow is not held to the guard's YAML subset.
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8").replace("\r\n", "\n")
        job = re.search(r"\n  ha-compose-example:\n(.*?)(?=\n  [a-z][a-z0-9-]*:\n|\Z)", workflow, re.DOTALL)
        self.assertIsNotNone(job)
        # The job waits for this run's image and must still run when that
        # build did not succeed, so its only condition is `always()`.
        conditions = re.findall(r"\n    if: (.*)", job.group(1))
        self.assertEqual(conditions, ["${{ always() }}"])
        steps = re.split(r"\n      - ", job.group(1))
        names = [step.split("\n", 1)[0] for step in steps]
        index = names.index("name: Check the shipped examples' PostgreSQL connection budgets")
        step = steps[index]
        # Nothing may make the step conditional or let it fail quietly.
        self.assertNotRegex(step, r"\n        (if|continue-on-error|working-directory|env):")
        self.assertIn("\n        shell: bash\n", step)
        self.assertIn("python -m unittest discover -s scripts -p test_pool_sizing.py -v", step)
        self.assertIn("--profile bootstrap --profile import config --format json", step)
        self.assertIn(f"python scripts/pool_sizing.py examples --rendered {COMPOSE_EXAMPLE}=", step)
        self.assertLess(index, names.index("name: Load the production image"))


if __name__ == "__main__":
    unittest.main()
