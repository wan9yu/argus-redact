"""Self-check for `reachability_gate.py`'s junit classifier and id matching.

The gate's whole job hinges on correctly telling "this testcase actually ran"
apart from "this testcase was collected but never ran" from a junit-xml
`<testcase>` element. Get that classification wrong and the gate either
false-greens (treats a never-run test as executed) or false-reds (treats an
xfail as never-run and blocks on it forever). These tests pin the classifier
against small, inline junit fixtures instead of a real pytest subprocess run,
so they stay fast and hermetic.
"""

from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree as ET

from tests.architecture.reachability_gate import (
    canonical_id,
    classify_testcase,
    parse_junit_executions,
    resolve_junit_paths,
    union_executions,
)


def _testcase(inner_xml: str, classname: str = "tests.pkg.test_mod", name: str = "test_fn"):
    xml = f'<testcase classname="{classname}" name="{name}" time="0.001">{inner_xml}</testcase>'
    return ET.fromstring(xml)


class TestClassifyTestcase:
    def test_plain_pass_with_no_child_is_executed(self):
        tc = _testcase("")
        assert classify_testcase(tc) is True

    def test_failure_child_is_executed(self):
        tc = _testcase('<failure message="boom">traceback...</failure>')
        assert classify_testcase(tc) is True

    def test_error_child_is_executed(self):
        tc = _testcase('<error message="setup blew up">traceback...</error>')
        assert classify_testcase(tc) is True

    def test_pytest_xfail_skip_is_executed(self):
        # A strict=False xfail that failed as expected: pytest reports it as
        # a <skipped type="pytest.xfail">, but the test body ran.
        tc = _testcase('<skipped type="pytest.xfail" message="reason: known bug"/>')
        assert classify_testcase(tc) is True

    def test_xpass_reported_as_typeless_skip_is_executed(self):
        # A non-strict xfail that unexpectedly passed is reported as a
        # typeless <skipped> with this exact message — the body still ran.
        tc = _testcase(
            '<skipped message="xfail-marked test passes unexpectedly">traceback...</skipped>'
        )
        assert classify_testcase(tc) is True

    def test_pytest_skip_is_never_run(self):
        # skipif()/pytest.skip(): setup ran far enough to hit the skip call,
        # but the test body itself never executed.
        tc = _testcase('<skipped type="pytest.skip" message="starlette not installed"/>')
        assert classify_testcase(tc) is False

    def test_typeless_collection_skip_is_never_run(self):
        # e.g. pytest.importorskip() at module scope: the whole module never
        # imported, so nothing in it ran.
        tc = _testcase('<skipped message="collection skipped">some/path.py:1: reason</skipped>')
        assert classify_testcase(tc) is False


class TestCanonicalId:
    def test_matches_junit_classname_and_name_for_a_plain_function(self):
        nodeid = "tests/architecture/test_mod.py::test_fn"
        assert canonical_id(nodeid) == "tests.architecture.test_mod.test_fn"

    def test_matches_junit_classname_and_name_for_a_class_scoped_test(self):
        nodeid = "tests/architecture/test_mod.py::TestThing::test_fn"
        assert canonical_id(nodeid) == "tests.architecture.test_mod.TestThing.test_fn"

    def test_keeps_parametrize_brackets_on_the_name_segment(self):
        nodeid = "tests/architecture/test_mod.py::test_fn[case-1]"
        assert canonical_id(nodeid) == "tests.architecture.test_mod.test_fn[case-1]"


class TestJunitFileParsing:
    def _write(self, tmp_path: Path, testcases_xml: str) -> Path:
        junit = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<testsuites><testsuite name="pytest" tests="1">'
            f"{testcases_xml}"
            "</testsuite></testsuites>"
        )
        path = tmp_path / "junit.xml"
        path.write_text(junit, encoding="utf-8")
        return path

    def test_parses_id_from_classname_and_name(self, tmp_path):
        path = self._write(
            tmp_path,
            '<testcase classname="tests.architecture.test_mod" name="test_fn" time="0.01"/>',
        )
        results = parse_junit_executions(path)
        assert results == {"tests.architecture.test_mod.test_fn": True}

    def test_skip_type_pytest_skip_is_recorded_as_never_run(self, tmp_path):
        path = self._write(
            tmp_path,
            '<testcase classname="tests.architecture.test_mod" name="test_fn" time="0.01">'
            '<skipped type="pytest.skip" message="not installed"/>'
            "</testcase>",
        )
        results = parse_junit_executions(path)
        assert results == {"tests.architecture.test_mod.test_fn": False}


class TestUnionAndAllowlistBehaviour:
    def test_union_treats_a_test_executed_anywhere_as_executed(self, tmp_path):
        # Leg A never runs it (real skip); leg B runs it for real. The union
        # must count it as executed, not never-run.
        leg_a = tmp_path / "junit-a.xml"
        leg_a.write_text(
            '<testsuites><testsuite><testcase classname="tests.pkg.test_mod" '
            'name="test_fn"><skipped type="pytest.skip" message="skip"/></testcase>'
            "</testsuite></testsuites>",
            encoding="utf-8",
        )
        leg_b = tmp_path / "junit-b.xml"
        leg_b.write_text(
            '<testsuites><testsuite><testcase classname="tests.pkg.test_mod" '
            'name="test_fn"/></testsuite></testsuites>',
            encoding="utf-8",
        )

        executed, per_leg_counts = union_executions([leg_a, leg_b])

        assert executed == {"tests.pkg.test_mod.test_fn"}
        assert per_leg_counts == {str(leg_a): 1, str(leg_b): 1}

    def test_resolve_junit_paths_expands_a_glob_pattern(self, tmp_path):
        (tmp_path / "junit-x.xml").write_text("<testsuites/>", encoding="utf-8")
        (tmp_path / "junit-y.xml").write_text("<testsuites/>", encoding="utf-8")
        (tmp_path / "other.xml").write_text("<testsuites/>", encoding="utf-8")

        resolved = resolve_junit_paths([str(tmp_path / "junit-*.xml")])

        assert {p.name for p in resolved} == {"junit-x.xml", "junit-y.xml"}

    def test_resolve_junit_paths_accepts_an_explicit_literal_path(self, tmp_path):
        target = tmp_path / "junit-local.xml"
        target.write_text("<testsuites/>", encoding="utf-8")

        resolved = resolve_junit_paths([str(target)])

        assert resolved == [target]
