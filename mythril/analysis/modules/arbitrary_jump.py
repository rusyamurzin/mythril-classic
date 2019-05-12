import logging
import json

from mythril.analysis import solver
from mythril.analysis.modules.base import DetectionModule
from mythril.analysis.report import Issue
from mythril.analysis.swc_data import ARBITRARY_JUMP
from mythril.exceptions import UnsatError
from mythril.laser.ethereum.state.global_state import GlobalState

log = logging.getLogger(__name__)

class ArbitraryJumpModule(DetectionModule):
    """This module contains the detection code for assembly usage."""

    def __init__(self):
        """"""
        super().__init__(
            name="Arbitrary Jump",
            swc_id=ARBITRARY_JUMP,
            description="Checks for usage assembly instructions.",
            entrypoint="callback",
            pre_hooks=["MSTORE"],
        )

    def execute(self, state: GlobalState) -> list:
        """

        :param state:
        :return:
        """
        self._issues.extend(_analyze_state(state))
        return self.issues


def _analyze_state(state) -> list:
    """

    :param state:
    :return:
    """
    log.info("Arbitrary jump module: found MSTORE instruction")

    try:
        instruction = state.get_current_instruction()
        address = instruction["address"]
        description_tail = (
            "The use of assembly is error-prone and should be avoided."
            "Usage MSTORE instruction or assign operator in assembly block"
            "is able to point a function type variable to any code instruction."
        )

        #May be check for assembly in str(constraints) is reduntant
        constraints = state.mstate.constraints
        if "assembly" in str(constraints):
            log.debug("ASSEMBLY usage in function " + state.environment.active_function_name)
            transaction_sequence = solver.get_transaction_sequence(
                state, state.mstate.constraints
            )
            debug = json.dumps(transaction_sequence, indent=4)

            issue = Issue(
                contract=state.environment.active_account.contract_name,
                function_name=state.environment.active_function_name,
                address=address,
                swc_id=ARBITRARY_JUMP,
                title="ASSEMBLY usage",
                severity="Low",
                description_head="Arbitrary jump is possible.",
                description_tail=description_tail,
                bytecode=state.environment.code.bytecode,
                debug=debug,
                gas_used=(state.mstate.min_gas_used, state.mstate.max_gas_used),
            )
            return [issue]
        else:
            log.debug("ASSEMBLY usage not found in " + state.environment.active_function_name)
    except UnsatError:
        log.debug("no model found")

    return []


detector = ArbitraryJumpModule()
