from .data_dependencies import DataDependenciesAnalysis
from .live_definitions import LiveDefinitions
from .constants import OP_AFTER, OP_BEFORE
from .. import register_analysis


register_analysis(DataDependenciesAnalysis, 'DataDependencies')
