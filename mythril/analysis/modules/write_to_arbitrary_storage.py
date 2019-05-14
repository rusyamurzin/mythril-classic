import logging

from mythril.exceptions import UnsatError
from mythril.analysis.report import Issue
from mythril.analysis.swc_data import WRITE_TO_ARBITRARY_STORAGE
from mythril.analysis.modules.base import DetectionModule
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.ethereum.util import get_concrete_int

log = logging.getLogger(__name__)

DESCRIPTION = '''
This module finds write to arbitrary storage vulnerabilities.
The following webpages contains an extensive description of the vulnerability: 
https://smartcontractsecurity.github.io/SWC-registry/docs/SWC-124
https://github.com/Arachnid/uscc/tree/master/submissions-2017/doughoyte
'''


class WriteToStorageModule(DetectionModule):
    """This module finds write to arbitrary storage vulnerabilities"""

    def __init__(self) -> None:
        """"""
        super().__init__(
            name="Write to arbitrary storage",
            swc_id=WRITE_TO_ARBITRARY_STORAGE,
            description=DESCRIPTION,
            entrypoint="callback",
            pre_hooks=["SSTORE"],
        )

    def execute(self, state: GlobalState) -> list:
        """

        :param state:
        :return:
        """
        log.debug("Executing module: Write to arbitrary storage")
        self._issues.extend(_analyze_state(state))
        return self.issues


def _analyze_state(state: GlobalState) -> list:
    """ Executes the analysis module"""
    issues = []

    try:
        instruction = state.get_current_instruction()

        stack = state.mstate.stack
        try:
            index = get_concrete_int(stack[-1])
        except TypeError:
            return []

        size_of_storage = state.mstate.memory_size

        if index > size_of_storage:
            issue = Issue(
                contract=state.node.contract_name,
                function_name=state.node.function_name,
                address=instruction["address"],
                swc_id=WRITE_TO_ARBITRARY_STORAGE,
                bytecode=state.environment.code.bytecode,
                title="Write to arbitrary storage location",
                severity="Medium",
                description_head="A possible write to arbitrary storage location vulnerability exists in function {}.".format(
                    state.node.function_name),
                description_tail="Index to write in storage location is {}.".format(index),
                gas_used=(state.mstate.min_gas_used, state.mstate.max_gas_used),
            )
            issues.append(issue)
    except UnsatError:
        return []
    return issues


detector = WriteToStorageModule()
