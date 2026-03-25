"""Condition bytecode compiler and stack VM.

Compiles PolicyCondition lists into a compact bytecode program that
evaluates without dot-path traversal or dynamic dispatch at runtime.

Opcodes:
    LOAD_FIELD <field_index>    Push resolved field value onto stack
    LOAD_CONST <const_index>   Push constant value onto stack
    CMP_EQ                     Pop 2, push (a == b)
    CMP_NEQ                    Pop 2, push (a != b)
    CMP_GT                     Pop 2, push (a > b)
    CMP_GTE                    Pop 2, push (a >= b)
    CMP_LT                     Pop 2, push (a < b)
    CMP_LTE                    Pop 2, push (a <= b)
    CMP_IN                     Pop 2, push (a in b)
    CMP_NOT_IN                 Pop 2, push (a not in b)
    CMP_CONTAINS               Pop 2, push (b in a)
    CMP_MATCHES                Pop 2, push (regex match)
    AND                        Pop 2, push (a and b)
    HALT_TRUE                  Return True (all conditions met)
    HALT_FALSE                 Return False (condition failed)
"""

from __future__ import annotations

import re
from enum import IntEnum, auto
from typing import Any

from antihero.policy.schema import PolicyCondition


class Op(IntEnum):
    """Bytecode opcodes."""

    LOAD_FIELD = auto()
    LOAD_CONST = auto()
    CMP_EQ = auto()
    CMP_NEQ = auto()
    CMP_GT = auto()
    CMP_GTE = auto()
    CMP_LT = auto()
    CMP_LTE = auto()
    CMP_IN = auto()
    CMP_NOT_IN = auto()
    CMP_CONTAINS = auto()
    CMP_MATCHES = auto()
    AND = auto()
    HALT_TRUE = auto()
    HALT_FALSE = auto()

    # Jump if false — skip remaining conditions
    JMP_IF_FALSE = auto()


# Map operator strings to opcodes
_OP_MAP: dict[str, Op] = {
    "eq": Op.CMP_EQ,
    "neq": Op.CMP_NEQ,
    "gt": Op.CMP_GT,
    "gte": Op.CMP_GTE,
    "lt": Op.CMP_LT,
    "lte": Op.CMP_LTE,
    "in": Op.CMP_IN,
    "not_in": Op.CMP_NOT_IN,
    "contains": Op.CMP_CONTAINS,
    "matches": Op.CMP_MATCHES,
}


class CompiledConditions:
    """A compiled bytecode program for evaluating conditions."""

    __slots__ = ("bytecode", "fields", "constants", "field_paths", "_regex_cache")

    def __init__(
        self,
        bytecode: list[tuple[Op, int]],
        fields: list[str],
        constants: list[Any],
        field_paths: list[list[str]],
    ) -> None:
        self.bytecode = bytecode
        self.fields = fields
        self.constants = constants
        self.field_paths = field_paths
        self._regex_cache: dict[int, re.Pattern[str]] = {}

    @property
    def is_empty(self) -> bool:
        """True if there are no conditions to evaluate."""
        return len(self.bytecode) == 0 or (
            len(self.bytecode) == 1 and self.bytecode[0][0] == Op.HALT_TRUE
        )


class ConditionCompiler:
    """Compiles PolicyCondition lists into bytecode."""

    def compile(self, conditions: list[PolicyCondition]) -> CompiledConditions:
        """Compile a list of conditions into bytecode.

        Conditions use AND semantics — all must pass. The bytecode uses
        short-circuit evaluation: first failure jumps to HALT_FALSE.
        """
        if not conditions:
            return CompiledConditions(
                bytecode=[(Op.HALT_TRUE, 0)],
                fields=[],
                constants=[],
                field_paths=[],
            )

        bytecode: list[tuple[Op, int]] = []
        fields: list[str] = []
        constants: list[Any] = []
        field_paths: list[list[str]] = []
        field_index_map: dict[str, int] = {}
        const_index_map: dict[int, int] = {}  # id(value) → index

        for i, cond in enumerate(conditions):
            # Register field
            if cond.field not in field_index_map:
                field_index_map[cond.field] = len(fields)
                fields.append(cond.field)
                field_paths.append(cond.field.split("."))
            field_idx = field_index_map[cond.field]

            # Register constant
            val_id = id(cond.value)
            if val_id not in const_index_map:
                const_index_map[val_id] = len(constants)
                constants.append(cond.value)
            const_idx = const_index_map[val_id]

            # Emit: LOAD_FIELD, LOAD_CONST, CMP_<op>
            bytecode.append((Op.LOAD_FIELD, field_idx))
            bytecode.append((Op.LOAD_CONST, const_idx))

            op = _OP_MAP.get(cond.operator)
            if op is None:
                # Unknown operator — condition always fails
                bytecode.append((Op.HALT_FALSE, 0))
                break

            bytecode.append((op, 0))

            # Short-circuit: if this condition failed, halt immediately
            bytecode.append((Op.JMP_IF_FALSE, 0))

        bytecode.append((Op.HALT_TRUE, 0))

        return CompiledConditions(
            bytecode=bytecode,
            fields=fields,
            constants=constants,
            field_paths=field_paths,
        )


def resolve_field(obj: Any, path: list[str]) -> Any:
    """Resolve a pre-split dot-path against an object. Zero-allocation."""
    for part in path:
        if isinstance(obj, dict):
            obj = obj.get(part)
        elif hasattr(obj, part):
            obj = getattr(obj, part)
        else:
            return None
    return obj


def execute_conditions(
    compiled: CompiledConditions,
    tce: Any,
) -> bool:
    """Execute compiled conditions against a TCE. Returns True if all pass.

    This is the hot-path function — no allocations, no exceptions, no dot-path
    splitting. Field paths are pre-split at compile time.
    """
    if compiled.is_empty:
        return True

    bc = compiled.bytecode
    fields = compiled.field_paths
    consts = compiled.constants
    stack: list[Any] = []
    ip = 0
    num_ops = len(bc)

    while ip < num_ops:
        op, arg = bc[ip]

        if op == Op.LOAD_FIELD:
            stack.append(resolve_field(tce, fields[arg]))
        elif op == Op.LOAD_CONST:
            stack.append(consts[arg])
        elif op == Op.CMP_EQ:
            b, a = stack.pop(), stack.pop()
            stack.append(a == b if a is not None else False)
        elif op == Op.CMP_NEQ:
            b, a = stack.pop(), stack.pop()
            stack.append(a != b if a is not None else True)
        elif op == Op.CMP_GT:
            b, a = stack.pop(), stack.pop()
            stack.append(a > b if a is not None else False)
        elif op == Op.CMP_GTE:
            b, a = stack.pop(), stack.pop()
            stack.append(a >= b if a is not None else False)
        elif op == Op.CMP_LT:
            b, a = stack.pop(), stack.pop()
            stack.append(a < b if a is not None else False)
        elif op == Op.CMP_LTE:
            b, a = stack.pop(), stack.pop()
            stack.append(a <= b if a is not None else False)
        elif op == Op.CMP_IN:
            b, a = stack.pop(), stack.pop()
            stack.append(a in b if a is not None else False)
        elif op == Op.CMP_NOT_IN:
            b, a = stack.pop(), stack.pop()
            stack.append(a not in b if a is not None else True)
        elif op == Op.CMP_CONTAINS:
            b, a = stack.pop(), stack.pop()
            stack.append(
                b in a if isinstance(a, (str, list, set, frozenset)) else False
            )
        elif op == Op.CMP_MATCHES:
            b, a = stack.pop(), stack.pop()
            if a is None:
                stack.append(False)
            else:
                # Use cached regex if available
                cache_key = id(b)
                if cache_key in compiled._regex_cache:
                    pat = compiled._regex_cache[cache_key]
                else:
                    pat = re.compile(str(b))
                    compiled._regex_cache[cache_key] = pat
                stack.append(bool(pat.search(str(a))))
        elif op == Op.JMP_IF_FALSE:
            if not stack[-1]:
                return False
        elif op == Op.HALT_TRUE:
            return True
        elif op == Op.HALT_FALSE:
            return False
        elif op == Op.AND:
            b, a = stack.pop(), stack.pop()
            stack.append(bool(a and b))

        ip += 1

    # Should not reach here, but fail-closed
    return False
