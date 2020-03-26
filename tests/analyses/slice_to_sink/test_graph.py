import networkx
import nose

from angr.analyses.slice_to_sink import context_sensitize, SliceToSink, slice_function_graph, slice_graph


class _MockCFGNode():
    def __init__(self, addr, function_address=None, graph=None):
        self.addr = addr
        self.function_address = function_address
        self.graph = graph
    def __repr__(self):
        return '%s' % self.addr
    def copy(self):
        return _MockCFGNode(self.addr, function_address=self.function_address, graph=self.graph)
    @property
    def predecessors(self):
        return list(self.graph.predecessors(self))
    @property
    def successors(self):
        return list(self.graph.successors(self))

def _a_graph_and_its_nodes():
    # Build the following graph (addresses displayed):
    # 0 -> 1, 1 -> 2, 0 -> 3
    graph = networkx.DiGraph()
    nodes = list(map(_MockCFGNode, range(4)))
    graph.add_edge(nodes[0], nodes[1])
    graph.add_edge(nodes[1], nodes[2])
    graph.add_edge(nodes[0], nodes[3])
    return (graph, nodes)


def test_slice_graph_remove_content_not_in_a_slice_to_sink():
    my_graph, nodes = _a_graph_and_its_nodes()

    transitions = {
        nodes[0].addr: [nodes[1].addr],
        nodes[1].addr: [nodes[2].addr]
    }
    my_slice = SliceToSink(None, transitions)

    sliced_graph = slice_graph(my_graph, my_slice)
    result_nodes = list(sliced_graph.nodes)
    result_edges = list(sliced_graph.edges)

    nose.tools.assert_list_equal(result_nodes, [nodes[0], nodes[1], nodes[2]])
    nose.tools.assert_list_equal(result_edges, [(nodes[0], nodes[1]), (nodes[1], nodes[2])])


def test_slice_graph_mutates_the_original_graph():
    my_graph, nodes = _a_graph_and_its_nodes()

    transitions = { nodes[0].addr: [nodes[1].addr] }
    my_slice = SliceToSink(None, transitions)

    sliced_graph = slice_graph(my_graph, my_slice)

    nose.tools.assert_equals(len(my_graph.nodes), 2)
    nose.tools.assert_equals(len(my_graph.edges), 1)
    nose.tools.assert_equals(my_graph, sliced_graph)


def test_slice_function_graph_remove_nodes_not_in_a_slice_to_sink():
    # Imagine a CFG being:    0 -> 0x42, 0x42 -> 1, 1 -> 2, 0 -> 3
    # And the function graph: 0 -> 1, 1 -> 2, 0 -> 3
    my_function_graph, nodes = _a_graph_and_its_nodes()

    transitions = { nodes[0].addr: [0x42], 0x42: [nodes[1].addr] }
    my_slice = SliceToSink(None, transitions)

    sliced_function_graph = slice_function_graph(my_function_graph, my_slice)
    result_nodes = list(sliced_function_graph.nodes)
    result_edges = list(sliced_function_graph.edges)

    nose.tools.assert_list_equal(result_nodes, [nodes[0], nodes[1]])
    nose.tools.assert_list_equal(result_edges, [(nodes[0], nodes[1])])


def test_slice_function_graph_mutates_the_original_function_graph():
    # Imagine a CFG being:    0 -> 0x42, 0x42 -> 1, 1 -> 2, 0 -> 3
    # And the function graph: 0 -> 1, 1 -> 2, 0 -> 3
    my_function_graph, nodes = _a_graph_and_its_nodes()

    transitions = { nodes[0].addr: [0x42], 0x42: [nodes[1].addr] }
    my_slice = SliceToSink(None, transitions)

    sliced_function_graph = slice_function_graph(my_function_graph, my_slice)

    nose.tools.assert_equals(len(my_function_graph.nodes), 2)
    nose.tools.assert_equals(len(my_function_graph.edges), 1)
    nose.tools.assert_equals(my_function_graph, sliced_function_graph)


def test_does_not_context_sensitize_function_if_called_only_once():
    # Build the following graph (addresses displayed):
    # 0 -> 1, 1 -> 2
    graph = networkx.DiGraph()
    nodes = list(map(
        lambda i: _MockCFGNode(i, graph=graph),
        range(3)
    ))
    graph.add_edge(nodes[0], nodes[1])
    graph.add_edge(nodes[1], nodes[2])
    setattr(nodes[1], 'function_address', 1)
    setattr(nodes[0], 'size', 2)
    # Make sure the test setup is correct
    assert nodes[0].addr + nodes[0].size == nodes[2].addr

    context_sensitive_graph = context_sensitize(graph)

    nose.tools.assert_equals(len(context_sensitive_graph.nodes), len(nodes))
    nose.tools.assert_list_equal(list(context_sensitive_graph.edges), [(nodes[0], nodes[1]), (nodes[1], nodes[2])])
    nose.tools.assert_equals(context_sensitive_graph, graph)


def test_context_sensitize_duplicates_a_function_block():
    # Build the following graph (addresses displayed):
    # 0 -> 2, 1 -> 2, 2 -> 3, 2 -> 4
    # Where:
    #   * 2 is the first block of a function
    #   * 0 calls 2, which returns to 3 => 0.addr + 0.size = 3.addr
    #   * 1 calls 2, which returns to 4 => 1.addr + 1.size = 4.addr
    graph = networkx.DiGraph()
    nodes = list(map(
        lambda i: _MockCFGNode(i, graph=graph),
        range(5)
    ))
    graph.add_edge(nodes[0], nodes[2])
    graph.add_edge(nodes[1], nodes[2])
    graph.add_edge(nodes[2], nodes[3])
    graph.add_edge(nodes[2], nodes[4])
    setattr(nodes[2], 'function_address', 2)
    setattr(nodes[0], 'size', 3)
    setattr(nodes[1], 'size', 3)
    # Make sure the test setup is correct
    assert nodes[0].successors == nodes[1].successors
    assert nodes[0].addr + nodes[0].size == nodes[3].addr
    assert nodes[1].addr + nodes[1].size == nodes[4].addr

    context_sensitive_graph = context_sensitize(graph)

    nose.tools.assert_equals(nodes[0].successors[0].addr, nodes[2].addr)
    nose.tools.assert_equals(nodes[1].successors[0].addr, nodes[2].addr)
    nose.tools.assert_not_equals(nodes[0].successors[0], nodes[1].successors[0])
    nose.tools.assert_equals(context_sensitive_graph, graph)


def test_context_sensitize_can_deal_with_calls_without_return():
    # Build the following graph (addresses displayed):
    # 0 -> 2, 1 -> 2, 2 -> 3
    # Where:
    #   * 2 is the first block of a function
    #   * 0 calls 2, which returns to 3 => 0.addr + 0.size = 3.addr
    #   * 1 calls 2, which does *NOT* return
    graph = networkx.DiGraph()
    nodes = list(map(
        lambda i: _MockCFGNode(i, graph=graph),
        range(4)
    ))
    graph.add_edge(nodes[0], nodes[2])
    graph.add_edge(nodes[1], nodes[2])
    graph.add_edge(nodes[2], nodes[3])
    setattr(nodes[2], 'function_address', 2)
    setattr(nodes[0], 'size', 3)
    setattr(nodes[1], 'size', 3)
    # Make sure the test setup is correct
    assert nodes[0].successors == nodes[1].successors
    assert nodes[0].addr + nodes[0].size == nodes[3].addr

    context_sensitive_graph = context_sensitize(graph)

    nose.tools.assert_equals(nodes[0].successors[0].addr, nodes[2].addr)
    nose.tools.assert_equals(nodes[1].successors[0].addr, nodes[2].addr)
    nose.tools.assert_not_equals(nodes[0].successors[0], nodes[1].successors[0])
    nose.tools.assert_equals(context_sensitive_graph, graph)


def test_context_sensitize_can_deal_with_function_never_called():
    # Build the following graph (addresses displayed):
    # 0 -> 2, 2 -> 1, 2 -> 3
    # Where:
    #   * 2 is the first block of a function
    #   * 0 calls 2, which returns to 3 => 0.addr + 0.size = 3.addr
    #   * 2 returns as well to 1 (e.g. undetected indirect jump to 2)
    graph = networkx.DiGraph()
    nodes = list(map(
        lambda i: _MockCFGNode(i, graph=graph),
        range(4)
    ))
    graph.add_edge(nodes[0], nodes[2])
    graph.add_edge(nodes[2], nodes[1])
    graph.add_edge(nodes[2], nodes[3])
    setattr(nodes[2], 'function_address', 2)
    setattr(nodes[0], 'size', 3)
    # Make sure the test setup is correct
    assert nodes[0].addr + nodes[0].size == nodes[3].addr

    context_sensitive_graph = context_sensitize(graph)

    nose.tools.assert_equals(nodes[0].successors[0].addr, nodes[2].addr)
    nose.tools.assert_not_equals(nodes[0].successors[0], nodes[2])
    nose.tools.assert_equals(context_sensitive_graph, graph)
