import os
import random

import nose

import archinfo
import angr

from angr.analyses.reaching_definitions.constants import OP_BEFORE
from angr.analyses.reaching_definitions.live_definitions import LiveDefinitions
from angr.analyses.reaching_definitions.subject import Subject, SubjectType


TESTS_LOCATION = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    '..', '..', '..', '..', 'binaries', 'tests'
)


class _MockFunctionSubject:
    class _MockFunction:
        def __init__(self):
            self.addr = 0x42

    def __init__(self):
        self.type = SubjectType.Function
        self.cc = None
        self.content = self._MockFunction()


def test_initializing_live_definitions_for_ppc_without_rtoc_value_should_raise_an_error():
    arch = archinfo.arch_ppc64.ArchPPC64()
    nose.tools.assert_raises(
       ValueError,
       LiveDefinitions, arch=arch, subject=_MockFunctionSubject()
    )


def test_initializing_live_definitions_for_ppc_with_rtoc_value():
    arch = archinfo.arch_ppc64.ArchPPC64()
    rtoc_value = random.randint(0, 0xffffffffffffffff)

    live_definition = LiveDefinitions(
       arch=arch, subject=_MockFunctionSubject(), rtoc_value=rtoc_value
    )

    rtoc_offset = arch.registers['rtoc'][0]
    rtoc_definition = next(iter(
        live_definition.register_definitions.get_objects_by_offset(rtoc_offset)
    ))
    rtoc_definition_value = rtoc_definition.data.get_first_element()

    nose.tools.assert_equals(rtoc_definition_value, rtoc_value)


def test_get_the_sp_from_a_reaching_definition():
    binary = os.path.join(TESTS_LOCATION, 'x86_64', 'all')
    project = angr.Project(binary, auto_load_libs=False)
    cfg = project.analyses.CFGFast()

    tmp_kb = angr.KnowledgeBase(project)
    main_func = cfg.kb.functions['main']
    rda = project.analyses.ReachingDefinitions(
        subject=main_func, kb=tmp_kb, observe_all=True
    )

    def _is_right_before_main_node(definition):
        bloc, ins_addr, op_type = definition[0]
        return (
            bloc == 'node' and
            ins_addr == main_func.addr and
            op_type == OP_BEFORE
        )

    reach_definition_at_main = next(filter(
        _is_right_before_main_node,
        rda.observed_results.items()
    ))[1]

    sp_value = reach_definition_at_main.get_sp()

    nose.tools.assert_equal(sp_value, project.arch.initial_sp)
