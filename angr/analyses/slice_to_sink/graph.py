def slice_graph(graph, slice_to_sink):
    """
    Slice a graph, keeping only the transitions and nodes present in the <SliceToSink> representation.

    *Note* that this function mutates the graph passed as an argument.

    :param networkx.DiGraph graph: The graph to slice.
    :param angr.analyses.slice_to_sink slice_to_sink:
        The representation of the slice, containing the data to update the CFG from.

    :return networkx.DiGraph: The sliced graph.
    """

    def _edge_in_slice_transitions(transitions, edge):
        if edge[0].addr not in transitions.keys():
            return False
        return edge[1].addr in slice_to_sink.transitions[edge[0].addr]

    original_edges = graph.edges()
    edges_to_remove = list(filter(
        lambda edge: not _edge_in_slice_transitions(slice_to_sink.transitions, edge),
        original_edges
    ))

    original_nodes = graph.nodes()
    nodes_to_remove = list(filter(
        lambda node: node.addr not in slice_to_sink.nodes,
        original_nodes
    ))

    graph.remove_edges_from(edges_to_remove)
    graph.remove_nodes_from(nodes_to_remove)

    return graph


def slice_function_graph(function_graph, slice_to_sink):
    """
    Slice a function graph, keeping only the nodes present in the <SliceToSink> representation.

    Because the <SliceToSink> is build from the CFG, and the function graph is *NOT* a subgraph of the CFG, edges of
    the function graph will no be present in the <SliceToSink> transitions.
    However, we use the fact that if there is an edge between two nodes in the function graph, then there must exist
    a path between these two nodes in the slice; Proof idea:
        The <SliceToSink> is backward and recursively constructed;
        If a node is in the slice, then all its predecessors will be (transitively);
        If there is an edge between two nodes in the function graph, there is a path between them in the CFG;
        So: The origin node is a transitive predecessor of the destination one, hence if destination is in the slice,
            then origin will be too.
    In consequence, in the end, removing the only nodes not present in the slice, and their related transitions gives
    us the expected result: a function graph representing (a higher view of) the flow in the slice.

    *Note* that this function mutates the graph passed as an argument.

    :param networkx.DiGraph graph: The graph to slice.
    :param angr.analyses.slice_to_sink slice_to_sink:
        The representation of the slice, containing the data to update the CFG from.

    :return networkx.DiGraph: The sliced graph.
    """

    original_nodes = function_graph.nodes()
    nodes_to_remove = list(filter(
        lambda node: node.addr not in slice_to_sink.nodes,
        original_nodes
    ))

    function_graph.remove_nodes_from(nodes_to_remove)

    return function_graph


def context_sensitize(graph):
    """
    Update a graph to make it "context-sensitive": duplicate blocks representing functions called more than once in the binary,
    so they have one entry point (coming from a `call`), and one exit point (representing a `return`).

    *Note* that this function mutates the graph passed as an argument.

    :param networkx.DiGraph graph: The graph to make context-sensitive.

    :return networkx.DiGraph: The updated graph.
    """
    def _node_and_its_return(predecessor, successors):
        potential_return = list(filter(
            lambda s: predecessor.addr + predecessor.size == s.addr,
            successors
        ))
        return None if len(potential_return) < 1 else (predecessor, potential_return[0])

    def _context_sensitize_function(graph, calling_node, return_node, function_node):
        """
        Context sensitize a function, for one specific call, and return.
        """
        if len(function_node.predecessors) == 1 and len(function_node.successors) == 1:
            return

        graph.remove_edge(calling_node, function_node)
        graph.remove_edge(function_node, return_node)

        new_function_node = function_node.copy()

        graph.add_node(new_function_node)
        graph.add_edge(calling_node, new_function_node)
        graph.add_edge(new_function_node, return_node)


    function_nodes = list(filter(
        lambda n: n.addr == n.function_address and (len(n.predecessors) > 1 or len(n.successors) > 1),
        graph.nodes()
    ))

    for function_node in function_nodes:
        calling_nodes_and_returns = list(filter(
            None.__ne__,
            map(
                lambda p: _node_and_its_return(p, function_node.successors),
                function_node.predecessors
            )
        ))

        for calling_node, return_node in calling_nodes_and_returns:
            _context_sensitize_function(graph, calling_node, return_node, function_node)

    return graph
