import logging
import re

from copy import copy, deepcopy
from typing import cast, List, Optional
from mythril.analysis import solver
from mythril.analysis.ops import *
from mythril.analysis.report import Issue
from mythril.exceptions import UnsatError
from mythril.analysis.swc_data import TX_ORDER_DEPENDENCE
from mythril.analysis.modules.base import DetectionModule
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.analysis.call_helpers import get_call_from_state
from mythril.laser.ethereum.state.annotation import StateAnnotation

log = logging.getLogger(__name__)

DESCRIPTION = '''
This module finds the existance of transaction order dependence vulnerabilities.
The following webpage contains an extensive description of the vulnerability: 
https://consensys.github.io/smart-contract-best-practices/known_attacks/#front-running-aka-transaction-ordering-dependence
'''


class TransactionOrderAnnotation(StateAnnotation):
    def __init__(self) -> None:
        self.calls = []  # type: List[Optional[Call]]

    def __copy__(self):
        result = TransactionOrderAnnotation()
        result.calls = copy(self.calls)
        return result


class TODModule(DetectionModule):
    """This module finds the existance of transaction order dependence vulnerabilities"""

    def __init__(self) -> None:
        """"""
        super().__init__(
            name="Transaction-Ordering Dependence",
            swc_id=TX_ORDER_DEPENDENCE,
            description=DESCRIPTION,
            entrypoint="callback",
            pre_hooks=["CALL", "SUICIDE"],
        )

    def execute(self, state: GlobalState) -> list:
        """

        :param state:
        :return:
        """
        log.debug("Executing module: TX_ORDER_DEPENDENCE")
        self._issues.extend(_analyze_state(state))
        return self.issues


def _analyze_state(state: GlobalState) -> list:
    """ Executes the analysis module"""
    issues = []

    instruction = state.get_current_instruction()

    annotations = cast(
        List[TransactionOrderAnnotation],
        list(state.get_annotations(TransactionOrderAnnotation)),
    )

    if len(annotations) == 0:
        log.debug("Creating annotation for state")
        state.annotate(TransactionOrderAnnotation())
        annotations = cast(
            List[TransactionOrderAnnotation],
            list(state.get_annotations(TransactionOrderAnnotation)),
        )

    calls = annotations[0].calls

    if instruction["opcode"] in ["CALL", "SUICIDE"]:
        call = get_call_from_state(state)
        if call:
            calls += [call]

    for call in calls:
        # Do analysis
        interesting_storages = list(_get_influencing_storages(call))
        changing_sstores = list(_get_influencing_sstores(state, interesting_storages))

        # Build issue if necessary
        if len(changing_sstores) > 0:
            node = call.node
            instruction = call.state.get_current_instruction()
            issue = Issue(
                contract=node.contract_name,
                function_name=node.function_name,
                address=instruction["address"],
                swc_id=TX_ORDER_DEPENDENCE,
                bytecode=state.environment.code.bytecode,
                title="Transaction order dependence",
                severity="Medium",
                description_head="A possible transaction-ordering dependence vulnerability exists in function {}.".format(node.function_name),
                description_tail=" The value or direction of the call statement is determined from a tainted storage location",
                gas_used=(state.mstate.min_gas_used, state.mstate.max_gas_used),
            )
            issues.append(issue)

    return issues


def _get_states_with_opcode(state, opcode):
    """ Gets all (state, node) tuples in statespace with opcode"""
    #for k in statespace.nodes:
    #    node = statespace.nodes[k]
    #       for state in node.states:
    if state.get_current_instruction()["opcode"] == opcode:
        yield state


def _dependent_on_storage(expression):
    """ Checks if expression is dependent on a storage symbol and returns the influencing storages"""
    pattern = re.compile(r"storage_[a-z0-9_&^]*[0-9]+")
    return pattern.findall(str(simplify(expression)))


def _get_storage_variable(storage, state):
    """
    Get storage z3 object given storage name and the state
    :param storage: storage name example: storage_0
    :param state: state to retrieve the variable from
    :return: z3 object representing storage
    """
    index = int(re.search('[0-9]+', storage).group())
    try:
        return state.environment.active_account.storage[index]
    except KeyError:
        return None


def _can_change(constraints, variable):
    """ Checks if the variable can change given some constraints """
    _constraints = deepcopy(constraints)
    try:
        model = solver.get_model(_constraints)
    except UnsatError:
        return False
    try:
        initial_value = int(str(model.eval(variable, model_completion=True)))
        return _try_constraints(constraints, [variable != initial_value]) is not None
    except AttributeError:
        return False


def _get_influencing_storages(call):
    """ Examines a Call object and returns an iterator of all storages that influence the call value or direction"""
    state = call.state
    node = call.node

    # Get relevant storages
    to, value = call.to, call.value
    storages = []
    if to.type == VarType.SYMBOLIC:
        storages += _dependent_on_storage(to.val)
    if value.type == VarType.SYMBOLIC:
        storages += _dependent_on_storage(value.val)

    # See if they can change within the constraints of the node
    for storage in storages:
        variable = _get_storage_variable(storage, state)
        can_change = _can_change(node.constraints, variable)
        if can_change:
            yield storage


def _get_influencing_sstores(statespace, interesting_storages):
    """ Gets sstore (state, node) tuples that write to interesting_storages"""
    for sstore_state in _get_states_with_opcode(statespace, 'SSTORE'):
        index, value = sstore_state.mstate.stack[-1], sstore_state.mstate.stack[-2]
        try:
            index = util.get_concrete_int(index)
        except AttributeError:
            index = str(index)
        if "storage_{}".format(index) not in interesting_storages:
            continue

        yield sstore_state


def _try_constraints(constraints, new_constraints):
    """
    Tries new constraints
    :return Model if satisfiable otherwise None
    """
    _constraints = deepcopy(constraints)
    for constraint in new_constraints:
        _constraints.append(deepcopy(constraint))
    try:
        model = solver.get_model(_constraints)
        return model
    except UnsatError:
        return None


detector = TODModule()
