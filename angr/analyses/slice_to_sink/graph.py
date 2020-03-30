from functools import reduce


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

    def _context_sensitize_function(graph, calling_edge, return_edge, function_nodes, function_edges):
        """
        Context sensitize the set of blocks making a function, for one specific call, and return.
        """
        def _duplicate(graph, nodes, edges):
            """
            Duplicate a set of nodes (and their inner relationships) in a graph.
            """
            new_nodes = dict(map(
                lambda n: (n, n.copy()),
                nodes
            ))
            for edge in edges:
                new_origin = new_nodes[edge[0]]
                new_destination = new_nodes[edge[1]]
                graph.add_edge(new_origin, new_destination)
            return new_nodes

        # If there is a single call and a single return, there is nothing to context-sensitize.
        if len(calling_edge[1].predecessors) == 1 and len(return_edge[0].successors) == 1:
            return

        graph.remove_edge(*calling_edge)
        graph.remove_edge(*return_edge)

        new_function_nodes = _duplicate(graph, function_nodes, function_edges)
        new_function_entry = new_function_nodes[calling_edge[1]]
        new_function_last_node = new_function_nodes[return_edge[0]]

        graph.add_edge(calling_edge[0], new_function_entry)
        graph.add_edge(new_function_last_node, return_edge[1])

    def _node_successors_for_function(node):
        """
        :return Tuple[List[Tuple[CFGNode,CFGNode]],List[Tuple[CFGNode,CFGNode]],List[CFGNode],List[CFGNode]]:
            Returns:
              * The list of edges belonging to the same function as the node given in parameter;
              * The list of edges leaving the function (returns);
              * The list of CFGNodes belonging to the same function as the node given in parameter;
              * The list of CFGNodes to which the function given as parameter returns to.
        """
        all_successors = set(node.successors)

        direct_successors_in_same_function = set(filter(
            lambda s: s.function_address == node.function_address,
            all_successors
        ))

        direct_edges_in_function = set(map(
            lambda s: (node, s),
            direct_successors_in_same_function
        ))

        direct_successors_not_in_same_function = all_successors - direct_successors_in_same_function

        direct_return_edges = set(map(
            lambda s: (node, s),
            direct_successors_not_in_same_function
        ))

        def _acc(acc, successor):
            edges_in, return_edges, successors_in, successors_not_in = _node_successors_for_function(successor)
            return (
                acc[0] | edges_in,
                acc[1] | return_edges,
                acc[2] | successors_in,
                acc[3] | successors_not_in
            )

        return reduce(
            lambda acc, s: _acc(acc, s),
            direct_successors_in_same_function,
            (
                direct_edges_in_function,
                direct_return_edges,
                direct_successors_in_same_function,
                direct_successors_not_in_same_function
            )
        )

    def _called_simprocedure(function):
        if len(function.successors) != 1:
            return None
        successor = function.successors[0]
        return successor if successor.is_simprocedure else None


    # Blocks to context-sensitize are:
    #   * function entrypoints
    #   * called or returning more than once
    #   * not simprocedures
    function_entries = list(filter(
        lambda n: (
            n.addr == n.function_address
            and (len(n.predecessors) > 1 or len(n.successors) > 1)
            and n.is_simprocedure == False
        ),
        graph.nodes()
    ))

    function_and_simprocedure_entries = list(map(
        lambda f: (f, _called_simprocedure(f)),
        function_entries
    ))

    for (function_entry, simprocedure_entry) in function_and_simprocedure_entries:
        f_edges, f_return_edges, f_nodes, f_returns = _node_successors_for_function(
            simprocedure_entry or function_entry
        )

        function_edges = list(f_edges)
        function_nodes = list({ function_entry } | f_nodes)
        if simprocedure_entry:
            function_edges += [(function_entry, simprocedure_entry)]
            function_nodes += [ simprocedure_entry ]
        function_returns = list(f_returns)
        function_return_edges = list(f_return_edges)

        calling_nodes_and_returns = list(filter(
            None.__ne__,
            map(
                lambda p: _node_and_its_return(p, function_returns),
                function_entry.predecessors
            )
        ))

        for calling_node, return_node in calling_nodes_and_returns:
            calling_edge = (calling_node, function_entry)
            return_edge = list(filter(
                lambda e: e[1] == return_node,
                function_return_edges
            ))[0]

            _context_sensitize_function(graph, calling_edge, return_edge, function_nodes, function_edges)

    return graph
