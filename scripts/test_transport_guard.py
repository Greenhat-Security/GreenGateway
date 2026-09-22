"""Harmless policy and pipeline regressions; no fixture opens a connection."""
import copy
import json
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest import mock
import transport_guard as guard

class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy=guard.read(guard.POLICY)

    def test_current_exact_policy_is_valid(self):
        guard.validate_policy(self.policy)
        guard.compare_scopes([{k:v for k,v in s.items() if k not in {"owner","purpose"}} for s in self.policy["scopes"]],self.policy["scopes"])

    def test_broad_file_or_scope_exception_rejected(self):
        for field,value in [("file","gateway/src/**"),("file","../outside.rs"),("file","/absolute.rs"),("scope","*"),("sha256","*")]:
            with self.subTest(field=field,value=value):
                p=copy.deepcopy(self.policy);p["scopes"][0][field]=value
                with self.assertRaises(ValueError):guard.validate_policy(p)

    def test_missing_owner_purpose_or_duplicate_scope_rejected(self):
        for field in ["owner","purpose"]:
            p=copy.deepcopy(self.policy);p["scopes"][0][field]=""
            with self.assertRaises(ValueError):guard.validate_policy(p)
        p=copy.deepcopy(self.policy);p["scopes"].append(copy.deepcopy(p["scopes"][0]))
        with self.assertRaises(ValueError):guard.validate_policy(p)

    def test_unknown_policy_field_cannot_hide_bypass(self):
        self.policy["ignore_directories"]=["gateway/src"]
        with self.assertRaises(ValueError):guard.validate_policy(self.policy)

    def test_changed_new_and_removed_scopes_fail_exact_comparison(self):
        actual=[{k:v for k,v in s.items() if k not in {"owner","purpose"}} for s in self.policy["scopes"]]
        for kind in ["changed","new","removed"]:
            with self.subTest(kind=kind):
                current=copy.deepcopy(actual)
                if kind=="changed":current[0]["sha256"]="a"*64
                if kind=="new":current.append({**current[0],"scope":"unreviewed_socket#1"})
                if kind=="removed":current.pop()
                with self.assertRaisesRegex(ValueError,"review required"):guard.compare_scopes(current,self.policy["scopes"])

    def test_empty_enumeration_is_failure(self):
        with mock.patch.object(guard,"run",return_value=""):
            with self.assertRaisesRegex(ValueError,"no Rust source"):guard.enumeration({})

class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.metadata=json.loads(guard.run("cargo","metadata","--locked","--all-features","--format-version","1"))
        cls.lock=(guard.ROOT/"Cargo.lock").read_text(encoding="utf-8")
        cls.policy=guard.read(guard.POLICY)
        cls.original_root=guard.ROOT

    def run_changed_input(self, change):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()
            metadata=copy.deepcopy(self.metadata)
            for p in metadata["packages"]:
                if p["id"] in metadata["workspace_members"]:
                    for target in p["targets"]:
                        target["src_path"]=str(root/Path(target["src_path"]).resolve().relative_to(self.original_root))
            lock=self.lock
            if change=="package":
                # Inert metadata only: this package is never fetched or compiled.
                identity=guard.REGISTRY+"#fixture-network-client@0.0.0"
                package=copy.deepcopy(next(p for p in metadata["packages"] if p["source"]==guard.REGISTRY))
                package.update(id=identity,name="fixture-network-client",version="0.0.0")
                metadata["packages"].append(package)
                metadata["resolve"]["nodes"].append({"id":identity,"dependencies":[],"deps":[],"features":[]})
                lock+='\n[[package]]\nname = "fixture-network-client"\nversion = "0.0.0"\nsource = "'+guard.REGISTRY+'"\nchecksum = "'+'0'*64+'"\n'
            elif change=="feature":
                metadata["resolve"]["nodes"][0]["features"].append("fixture-network-feature")
            elif change=="registry":
                lock=lock.replace(guard.REGISTRY,"registry+https://registry.invalid/index",1)
            elif change=="build":
                pass
            (root/"Cargo.lock").write_text(lock,encoding="utf-8")
            policy_path=root/"transport-ownership.json";guard.write(policy_path,self.policy)
            build=copy.deepcopy(self.policy["build_inputs"])
            if change=="build":build[0]["sha256"]="f"*64
            output=root/"output"
            with mock.patch.multiple(guard,ROOT=root,POLICY=policy_path,OUTPUT=output), mock.patch.object(guard,"run",return_value=json.dumps(metadata)) as command, mock.patch.object(guard,"enumeration",return_value=({"files":[],"roots":[]},build)):
                with self.assertRaises(ValueError):guard.check()
            decision=guard.read(output/"decision.json")
            self.assertEqual(decision["status"],"failed")
            self.assertFalse(any("run" in call.args for call in command.call_args_list),"unreviewed inputs must fail before compiling the syntax tool")
            return decision,command.call_count

    def test_new_network_package_fails_before_compilation(self):
        decision,count=self.run_changed_input("package")
        self.assertEqual(decision["stage"],"dependency-review")
        self.assertEqual(count,1)

    def test_new_feature_fails_before_compilation(self):
        decision,_=self.run_changed_input("feature")
        self.assertEqual(decision["stage"],"dependency-review")

    def test_unknown_registry_fails_before_metadata_fetch(self):
        decision,count=self.run_changed_input("registry")
        self.assertEqual(count,0)
        self.assertIn("before metadata",decision["error"])

    def test_changed_build_script_requires_generated_code_review(self):
        decision,_=self.run_changed_input("build")
        self.assertIn("generated code",decision["error"])


class StandalonePolicyTests(unittest.TestCase):
    def entry(self):
        return {"file":"scripts/benchmarks/fixture.rs","sha256":"a"*64,
                "owner":"GreenGateway maintainers",
                "purpose":"Review this exact standalone measurement harness."}

    def test_schema_one_cannot_omit_standalone_review(self):
        for version in (1,True,2.0):
            policy=guard.read(guard.POLICY);policy["schema"]=version
            with self.subTest(version=version),self.assertRaises(ValueError):
                guard.validate_policy(policy)

    def test_exact_paths_reject_globs_escapes_and_other_source_directories(self):
        for file in ("gateway/src/main.rs","scripts/benchmarks/**.rs","scripts/benchmarks/../main.rs",
                     "/scripts/benchmarks/fixture.rs","scripts\\benchmarks\\fixture.rs",
                     "scripts/benchmarks/fixture.txt","scripts/benchmarks//fixture.rs",
                     "scripts/benchmarks/./fixture.rs"):
            entry=self.entry();entry["file"]=file
            with self.subTest(file=file),self.assertRaises(ValueError):
                guard.validate_standalone_entries([entry])

    def test_duplicate_missing_and_unreviewed_entries_fail(self):
        original=self.entry()
        variants=[[original,copy.deepcopy(original)]]
        for field in original:
            entry=copy.deepcopy(original);del entry[field];variants.append([entry])
        for field in ("owner","purpose","sha256"):
            entry=copy.deepcopy(original);entry[field]="";variants.append([entry])
        variants.extend([None,{},["fixture.rs"]])
        for entries in variants:
            with self.subTest(entries=entries),self.assertRaises(ValueError):
                guard.validate_standalone_entries(entries)

    def test_source_digest_normalizes_line_endings_and_rejects_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/"scripts/benchmarks/fixture.rs"
            source.parent.mkdir(parents=True);source.write_bytes(b"fn main() {}\n")
            with mock.patch.object(guard,"ROOT",root):
                unix=guard.standalone_hash("scripts/benchmarks/fixture.rs")
                source.write_bytes(b"fn main() {}\r\n")
                self.assertEqual(guard.standalone_hash("scripts/benchmarks/fixture.rs"),unix)
                source.unlink()
                with self.assertRaises(ValueError):guard.standalone_hash("scripts/benchmarks/fixture.rs")
                target=root/"real.rs";target.write_text("fn main() {}\n")
                source.symlink_to(target)
                with self.assertRaisesRegex(ValueError,"symbolic links"):
                    guard.standalone_hash("scripts/benchmarks/fixture.rs")

    def test_registration_adds_a_parsed_root_without_dropping_any_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/"scripts/benchmarks/fixture.rs"
            source.parent.mkdir(parents=True);source.write_text("fn main() {}\n")
            with mock.patch.object(guard,"ROOT",root):
                entry=self.entry();entry["sha256"]=guard.standalone_hash(entry["file"])
                manifest={"files":["gateway/src/main.rs",entry["file"],"unknown.rs"],
                          "roots":[{"file":"gateway/src/main.rs","name":"gateway","test":False,"kind":["bin"]}]}
                original=copy.deepcopy(manifest)
                actual=guard.standalone_roots(manifest,[entry])
                self.assertEqual(manifest,original)
                self.assertEqual(actual["files"],original["files"])
                self.assertEqual(actual["roots"][:-1],original["roots"])
                self.assertEqual(actual["roots"][-1]["file"],entry["file"])
                self.assertTrue(actual["roots"][-1]["test"])
                self.assertEqual(actual["roots"][-1]["kind"],["standalone-benchmark"])
                self.assertNotIn("::",actual["roots"][-1]["name"])

    def test_cargo_target_conflict_is_rejected_for_either_role(self):
        entry=self.entry()
        for role in (False,True):
            manifest={"files":[entry["file"]],"roots":[{"file":entry["file"],"test":role}]}
            with self.subTest(role=role),self.assertRaisesRegex(ValueError,"Cargo target"):
                guard.standalone_roots(manifest,[entry])


class StandalonePipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        PipelineTests.setUpClass.__func__(cls)

    def fixture(self,change=None,inventory=False,explicit=False):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();metadata=copy.deepcopy(self.metadata)
            for package in metadata["packages"]:
                if package["id"] in metadata["workspace_members"]:
                    for target in package["targets"]:
                        target["src_path"]=str(root/Path(target["src_path"]).resolve().relative_to(self.original_root))
            (root/"Cargo.lock").write_text(self.lock,encoding="utf-8")
            file="scripts/benchmarks/fixture.rs";source=root/file
            source.parent.mkdir(parents=True);source.write_text("fn main() {}\n")
            policy=copy.deepcopy(self.policy)
            entry=StandalonePolicyTests().entry()
            with mock.patch.object(guard,"ROOT",root):entry["sha256"]=guard.standalone_hash(file)
            policy["standalone_benchmarks"]=[entry]
            manifest={"files":["gateway/src/main.rs",file],
                      "roots":[{"file":"gateway/src/main.rs","name":"gateway","test":False,"kind":["bin"]}]}
            facts={"schema":1,"files":{"gateway/src/main.rs":"production",file:"nonproduction"},
                   "scopes":[{key:value for key,value in scope.items() if key not in {"owner","purpose"}}
                             for scope in policy["scopes"]]}
            if change=="changed":source.write_text("fn main() { let _value = 1; }\n")
            elif change=="missing":source.unlink()
            elif change=="unregistered":manifest["files"].append("scripts/benchmarks/unregistered.rs")
            elif change=="cargo-root":manifest["roots"].append({"file":file,"name":"fixture","test":False,"kind":["bin"]})
            elif change=="unenumerated":manifest["files"].remove(file)
            elif change=="symlink":
                source.unlink();other=root/"other.rs";other.write_text("fn main() {}\n");source.symlink_to(other)
            policy_path=root/"transport-ownership.json";guard.write(policy_path,policy)
            output=root/"output"
            def command(*args):
                if args[:2]==("cargo","metadata"):return json.dumps(metadata)
                if args[:2]==("cargo","run"):
                    if change=="syntax":raise subprocess.CalledProcessError(1,args,stderr="invalid Rust fixture")
                    return json.dumps(facts)
                raise AssertionError(args)
            error=None
            with mock.patch.multiple(guard,ROOT=root,POLICY=policy_path,OUTPUT=output), \
                 mock.patch.object(guard,"run",side_effect=command) as process, \
                 mock.patch.object(guard,"enumeration",return_value=(manifest,policy["build_inputs"])):
                try:guard.check(inventory, [file] if explicit else [])
                except (ValueError,subprocess.CalledProcessError) as caught:error=caught
            decision=guard.read(output/"decision.json")
            candidate=guard.read(output/"candidate.json") if (output/"candidate.json").exists() else None
            enumeration=guard.read(output/"enumeration.json") if (output/"enumeration.json").exists() else None
            return error,decision,process.call_args_list,candidate,enumeration

    def test_registered_harness_is_sent_to_the_existing_syntax_tool(self):
        error,decision,calls,_,manifest=self.fixture()
        self.assertIsNone(error);self.assertEqual(decision["status"],"passed")
        self.assertTrue(any(call.args[:2]==("cargo","run") for call in calls))
        self.assertTrue(manifest["roots"][-1]["test"])
        self.assertIn("scripts/benchmarks/fixture.rs",manifest["files"])

    def test_changed_missing_linked_unenumerated_or_cargo_owned_files_fail_before_compile(self):
        for change in ("changed","missing","symlink","unenumerated","cargo-root"):
            with self.subTest(change=change):
                error,decision,calls,_,_=self.fixture(change)
                self.assertIsInstance(error,ValueError)
                self.assertEqual(decision["status"],"failed")
                self.assertEqual(decision["stage"],"standalone-review")
                self.assertFalse(any(call.args[:2]==("cargo","run") for call in calls))

    def test_unregistered_rust_still_fails_the_ownership_check(self):
        error,decision,_,_,_=self.fixture("unregistered")
        self.assertIsInstance(error,ValueError)
        self.assertEqual(decision["status"],"failed")
        self.assertIn("not owned",decision["error"])

    def test_syntax_failure_is_not_an_allowed_benchmark(self):
        error,decision,_,_,_=self.fixture("syntax")
        self.assertIsInstance(error,subprocess.CalledProcessError)
        self.assertEqual(decision["status"],"failed")
        self.assertEqual(decision["stage"],"syntax")

    def test_inventory_preserves_current_registration_and_requires_explicit_hash_refresh(self):
        error,decision,_,candidate,_=self.fixture(inventory=True)
        self.assertIsNone(error);self.assertEqual(decision["status"],"inventory")
        self.assertEqual(candidate["standalone_benchmarks"][0]["owner"],"GreenGateway maintainers")
        error,_,_,_,_=self.fixture("changed",inventory=True)
        self.assertIsInstance(error,ValueError)
        error,decision,_,candidate,_=self.fixture("changed",inventory=True,explicit=True)
        self.assertIsNone(error);self.assertEqual(decision["status"],"inventory")
        self.assertEqual(candidate["standalone_benchmarks"][0]["owner"],"")
        self.assertEqual(candidate["standalone_benchmarks"][0]["purpose"],"")
        with self.assertRaises(ValueError):guard.validate_policy(candidate)

    def test_check_cannot_accept_inventory_registration_flag(self):
        error,decision,calls,_,_=self.fixture(explicit=True)
        self.assertIsInstance(error,ValueError)
        self.assertEqual(decision["status"],"failed")
        self.assertEqual(calls,[])

if __name__=="__main__":unittest.main()
