"""Harmless policy and pipeline regressions; no fixture opens a connection."""
import copy
import json
from pathlib import Path
import tempfile
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

if __name__=="__main__":unittest.main()
