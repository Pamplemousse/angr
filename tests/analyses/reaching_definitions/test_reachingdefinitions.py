# Disable some pylint warnings: missing-docstring
# pylint: disable=R0201, C0111

import logging
import os
import pickle

import nose

import ailment
import angr
from angr.analyses.reaching_definitions.atoms import GuardUse, Tmp, Register
from angr.analyses.reaching_definitions.constants import OP_BEFORE, OP_AFTER
from angr.analyses.reaching_definitions.live_definitions import LiveDefinitions
from angr.analyses.reaching_definitions.subject import Subject
from angr.block import Block

LOGGER = logging.getLogger('test_reachingdefinitions')

TESTS_LOCATION = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    '..', '..', '..', '..', 'binaries', 'tests'
)


class InsnAndNodeObserveTestingUtils():
    @staticmethod
    def assert_equals_for_live_definitions(live_definition_1, live_definition_2):
        list(map(
            lambda attr: {\
                nose.tools.assert_equals(getattr(live_definition_1, attr),\
                                         getattr(live_definition_2, attr))\
            },
            ["register_definitions", "stack_definitions", "memory_definitions", "tmp_definitions"]
        ))

    @staticmethod
    def filter(observed_results, observation_points):
        # Return only the observed results associated with the observation points,
        # and do not fail if an observation point do not appear in the observed results.
        return list(map(
            lambda key: observed_results[key],
            filter(
                lambda key: key in observed_results,
                observation_points
            )
        ))

    @staticmethod
    def setup(observation_points):
        binary_path = os.path.join(TESTS_LOCATION, 'x86_64', 'all')
        project = angr.Project(binary_path, load_options={'auto_load_libs': False})
        cfg = project.analyses.CFGFast()

        main_function = cfg.kb.functions['main']
        reaching_definitions = project.analyses.ReachingDefinitions(
            subject=main_function, observation_points=observation_points
        )

        state = LiveDefinitions(
           project.arch, reaching_definitions.subject, project.loader
        )

        return (project, main_function, reaching_definitions, state)


def _run_reaching_definition_analysis_test(project, function, result_path, _extract_result):
    tmp_kb = angr.KnowledgeBase(project)
    reaching_definition = project.analyses.ReachingDefinitions(
        subject=function, kb=tmp_kb, observe_all=True
    )

    result = _extract_result(reaching_definition)

    # Uncomment these to regenerate the reference results... if you dare
    #with open(result_path, 'wb') as result_file:
    #    pickle.dump(result, result_file)
    with open(result_path, 'rb') as result_file:
        expected_result = pickle.load(result_file)

    nose.tools.assert_list_equal(result, expected_result)

def _binary_path(binary_name):
    return os.path.join(TESTS_LOCATION, 'x86_64', binary_name)

def _result_path(binary_results_name):
    return os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'results',
        'x86_64',
        binary_results_name + '.pickle'
    )


def test_reaching_definition_analysis_definitions():
    def _result_extractor(rda):
        unsorted_result = map(
            lambda x: {'key': x[0],\
                       'register_definitions': x[1].register_definitions._storage,\
                       'stack_definitions': x[1].stack_definitions._storage,\
                       'memory_definitions': x[1].memory_definitions._storage},
            rda.observed_results.items()
        )
        return list(sorted(
            unsorted_result,
            key=lambda x: x['key']
        ))

    binaries_and_results = list(map(
        lambda binary: (_binary_path(binary), _result_path(binary + '_definitions')),
        ['all', 'fauxware', 'loop']
    ))

    for binary, result_path in binaries_and_results:
        project = angr.Project(binary, load_options={'auto_load_libs': False})
        cfg = project.analyses.CFGFast()
        function = cfg.kb.functions['main']

        _run_reaching_definition_analysis_test(project, function, result_path, _result_extractor)


def test_reaching_definition_analysis_visited_blocks():
    def _result_extractor(rda):
        return rda.visited_blocks

    binaries_and_results = list(map(
        lambda binary: (_binary_path(binary), _result_path(binary + '_visited_blocks')),
        ['all', 'fauxware', 'loop']
    ))

    for binary, result_path in binaries_and_results:
        project = angr.Project(binary, load_options={'auto_load_libs': False})
        cfg = project.analyses.CFGFast()
        function = cfg.kb.functions['main']

        _run_reaching_definition_analysis_test(project, function, result_path, _result_extractor)


def test_node_observe():
    # Create several different observation points
    observation_points = [('node', 0x42, OP_AFTER), ('insn', 0x43, OP_AFTER)]

    _, _, reaching_definition, state =\
        InsnAndNodeObserveTestingUtils.setup(observation_points)

    reaching_definition.node_observe(0x42, state, OP_AFTER)

    results = InsnAndNodeObserveTestingUtils.filter(
        reaching_definition.observed_results,
        observation_points
    )
    expected_results = [state]

    nose.tools.assert_equals(results, expected_results)


def test_insn_observe_an_ailment_statement():
    # Create several different observation points
    observation_points = [('node', 0x42, OP_AFTER), ('insn', 0x43, OP_AFTER)]

    _, main_function, reaching_definition, state =\
        InsnAndNodeObserveTestingUtils.setup(observation_points)

    # Here, the statement content does not matter, neither if it is really in the block or else…
    statement = ailment.statement.DirtyStatement(0, None)
    block = main_function._addr_to_block_node[main_function.addr] # pylint: disable=W0212

    reaching_definition.insn_observe(0x43, statement, block, state, OP_AFTER)

    results = InsnAndNodeObserveTestingUtils.filter(
        reaching_definition.observed_results,
        observation_points
    )
    expected_results = [state]

    nose.tools.assert_greater(len(results), 0)
    list(map(
        lambda x: InsnAndNodeObserveTestingUtils.assert_equals_for_live_definitions(x[0], x[1]),
        zip(results, expected_results)
    ))


def test_insn_observe_before_an_imark_pyvex_statement():
    # Create several different observation points
    observation_points = [('node', 0x42, OP_AFTER), ('insn', 0x43, OP_BEFORE)]

    project, main_function, reaching_definition, state =\
        InsnAndNodeObserveTestingUtils.setup(observation_points)

    code_block = main_function._addr_to_block_node[main_function.addr] # pylint: disable=W0212
    block = Block(addr=0x43, byte_string=code_block.bytestr, project=project)
    statement = block.vex.statements[0]

    reaching_definition.insn_observe(0x43, statement, block, state, OP_BEFORE)

    results = InsnAndNodeObserveTestingUtils.filter(
        reaching_definition.observed_results,
        observation_points
    )
    expected_results = [state]

    nose.tools.assert_greater(len(results), 0)
    list(map(
        lambda x: InsnAndNodeObserveTestingUtils.assert_equals_for_live_definitions(x[0], x[1]),
        zip(results, expected_results)
    ))


def test_insn_observe_after_a_pyvex_statement():
    # Create several different observation points
    observation_points = [('node', 0x42, OP_AFTER), ('insn', 0x43, OP_AFTER)]

    project, main_function, reaching_definition, state =\
        InsnAndNodeObserveTestingUtils.setup(observation_points)

    code_block = main_function._addr_to_block_node[main_function.addr] # pylint: disable=W0212
    block = Block(addr=0x43, byte_string=code_block.bytestr, project=project)
    # When observing OP_AFTER an instruction, the statement has to be the last of a block
    # (or preceding an IMark)
    statement = block.vex.statements[-1]

    reaching_definition.insn_observe(0x43, statement, block, state, OP_AFTER)

    results = InsnAndNodeObserveTestingUtils.filter(
        reaching_definition.observed_results,
        observation_points
    )
    expected_results = [state]

    nose.tools.assert_greater(len(results), 0)
    list(map(
        lambda x: InsnAndNodeObserveTestingUtils.assert_equals_for_live_definitions(x[0], x[1]),
        zip(results, expected_results)
    ))


def test_reaching_definition_analysis_exposes_its_subject():
    binary_path = os.path.join(TESTS_LOCATION, 'x86_64', 'all')
    project = angr.Project(binary_path, load_options={'auto_load_libs': False})
    cfg = project.analyses.CFGFast()

    main_function = cfg.kb.functions['main']
    reaching_definitions = project.analyses.ReachingDefinitions(
        subject=main_function
    )

    nose.tools.assert_equals(reaching_definitions.subject.__class__ is Subject, True)


def test_dep_graph():
    project = angr.Project(os.path.join(TESTS_LOCATION, 'x86_64', 'true'), auto_load_libs=False)
    cfg = project.analyses.CFGFast()
    main = cfg.functions['main']

    # build a def-use graph for main() of /bin/true without tmps. check that the only dependency of the first block's guard is the four cc registers
    rda = project.analyses.ReachingDefinitions(subject=main, track_tmps=False)
    guard_use = list(filter(
        lambda def_: type(def_.atom) is GuardUse and def_.codeloc.block_addr == main.addr,
        rda.dep_graph._graph.nodes()
    ))[0]
    nose.tools.assert_equal(
        len(rda.dep_graph._graph.pred[guard_use]),
        4
    )
    nose.tools.assert_equal(
        all(type(def_.atom) is Register for def_ in rda.dep_graph._graph.pred[guard_use]),
        True
    )
    nose.tools.assert_equal(
        set(def_.atom.reg_offset for def_ in rda.dep_graph._graph.pred[guard_use]),
        {reg.vex_offset for reg in project.arch.register_list if reg.name.startswith('cc_')}
    )

    # build a def-use graph for main() of /bin/true. check that t7 in the first block is only used by the guard
    rda = project.analyses.ReachingDefinitions(subject=main, track_tmps=True)
    tmp_7 = list(filter(
        lambda def_: type(def_.atom) is Tmp and def_.atom.tmp_idx == 7 and def_.codeloc.block_addr == main.addr,
        rda.dep_graph._graph.nodes()
    ))[0]
    nose.tools.assert_equal(
        len(rda.dep_graph._graph.succ[tmp_7]),
        1
    )
    nose.tools.assert_equal(
        type(list(rda.dep_graph._graph.succ[tmp_7])[0].atom),
        GuardUse
    )


if __name__ == '__main__':
    LOGGER.setLevel(logging.DEBUG)
    logging.getLogger('angr.analyses.reaching_definitions').setLevel(logging.DEBUG)

    nose.core.runmodule()
