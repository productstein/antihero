"""Tests for condition bytecode compiler and VM."""

import pytest

from antihero.policy.schema import PolicyCondition
from antihero.realtime.bytecode import (
    CompiledConditions,
    ConditionCompiler,
    Op,
    execute_conditions,
)


class _FakeContext:
    """Minimal object for condition evaluation tests."""

    def __init__(self, **kwargs: object) -> None:
        for k, v in kwargs.items():
            setattr(self, k, v)


class TestConditionCompiler:
    """Test condition compilation."""

    def test_empty_conditions(self) -> None:
        compiler = ConditionCompiler()
        result = compiler.compile([])
        assert result.is_empty
        assert execute_conditions(result, _FakeContext())

    def test_single_eq(self) -> None:
        compiler = ConditionCompiler()
        conds = [PolicyCondition(field="action", operator="eq", value="file.write")]
        result = compiler.compile(conds)

        assert not result.is_empty
        assert execute_conditions(result, _FakeContext(action="file.write"))
        assert not execute_conditions(result, _FakeContext(action="file.read"))

    def test_single_gt(self) -> None:
        compiler = ConditionCompiler()
        conds = [PolicyCondition(field="risk", operator="gt", value=0.5)]
        result = compiler.compile(conds)

        assert execute_conditions(result, _FakeContext(risk=0.8))
        assert not execute_conditions(result, _FakeContext(risk=0.3))

    def test_multiple_and_conditions(self) -> None:
        compiler = ConditionCompiler()
        conds = [
            PolicyCondition(field="action", operator="eq", value="file.write"),
            PolicyCondition(field="risk", operator="lt", value=0.5),
        ]
        result = compiler.compile(conds)

        # Both true
        assert execute_conditions(
            result, _FakeContext(action="file.write", risk=0.3)
        )
        # First true, second false
        assert not execute_conditions(
            result, _FakeContext(action="file.write", risk=0.8)
        )
        # First false — short circuit
        assert not execute_conditions(
            result, _FakeContext(action="file.read", risk=0.3)
        )

    def test_contains_operator(self) -> None:
        compiler = ConditionCompiler()
        conds = [PolicyCondition(field="tags", operator="contains", value="admin")]
        result = compiler.compile(conds)

        assert execute_conditions(result, _FakeContext(tags=["admin", "user"]))
        assert not execute_conditions(result, _FakeContext(tags=["user"]))

    def test_matches_regex(self) -> None:
        compiler = ConditionCompiler()
        conds = [PolicyCondition(field="path", operator="matches", value=r"^/etc/.*")]
        result = compiler.compile(conds)

        assert execute_conditions(result, _FakeContext(path="/etc/passwd"))
        assert not execute_conditions(result, _FakeContext(path="/home/user"))

    def test_in_operator(self) -> None:
        compiler = ConditionCompiler()
        conds = [PolicyCondition(field="role", operator="in", value=["admin", "root"])]
        result = compiler.compile(conds)

        assert execute_conditions(result, _FakeContext(role="admin"))
        assert not execute_conditions(result, _FakeContext(role="user"))

    def test_not_in_operator(self) -> None:
        compiler = ConditionCompiler()
        conds = [PolicyCondition(field="role", operator="not_in", value=["blocked"])]
        result = compiler.compile(conds)

        assert execute_conditions(result, _FakeContext(role="admin"))
        assert not execute_conditions(result, _FakeContext(role="blocked"))

    def test_null_field_handling(self) -> None:
        compiler = ConditionCompiler()
        conds = [PolicyCondition(field="missing_field", operator="eq", value="x")]
        result = compiler.compile(conds)

        # Missing field → None → eq fails
        assert not execute_conditions(result, _FakeContext())

    def test_null_field_neq(self) -> None:
        compiler = ConditionCompiler()
        conds = [PolicyCondition(field="missing_field", operator="neq", value="x")]
        result = compiler.compile(conds)

        # Missing field → None → neq succeeds (None != "x")
        assert execute_conditions(result, _FakeContext())

    def test_dot_path_resolution(self) -> None:
        compiler = ConditionCompiler()
        conds = [PolicyCondition(field="subject.agent_id", operator="eq", value="bot-1")]
        result = compiler.compile(conds)

        subject = _FakeContext(agent_id="bot-1")
        assert execute_conditions(result, _FakeContext(subject=subject))

        subject2 = _FakeContext(agent_id="bot-2")
        assert not execute_conditions(result, _FakeContext(subject=subject2))

    def test_dict_path_resolution(self) -> None:
        compiler = ConditionCompiler()
        conds = [PolicyCondition(field="context.risk_score", operator="gte", value=0.5)]
        result = compiler.compile(conds)

        assert execute_conditions(result, _FakeContext(context={"risk_score": 0.7}))
        assert not execute_conditions(result, _FakeContext(context={"risk_score": 0.2}))

    def test_lte_operator(self) -> None:
        compiler = ConditionCompiler()
        conds = [PolicyCondition(field="force", operator="lte", value=50.0)]
        result = compiler.compile(conds)

        assert execute_conditions(result, _FakeContext(force=50.0))
        assert execute_conditions(result, _FakeContext(force=30.0))
        assert not execute_conditions(result, _FakeContext(force=51.0))
