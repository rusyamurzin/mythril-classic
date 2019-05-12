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
            pre_hooks=["ASSEMBLY"],
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
    log.info("Exceptions module: found ASSERT_FAIL instruction")

    log.debug("ASSERT_FAIL in function " + state.environment.active_function_name)

    try:
        address = state.get_current_instruction()["address"]

        description_tail = (
            "It is possible to trigger an exception (opcode 0xfe). "
            "Exceptions can be caused by type errors, division by zero, "
            "out-of-bounds array access, or assert violations. "
            "Note that explicit `assert()` should only be used to check invariants. "
            "Use `require()` for regular input checking."
        )

        transaction_sequence = solver.get_transaction_sequence(
            state, state.mstate.constraints
        )
        debug = json.dumps(transaction_sequence, indent=4)

        issue = Issue(
            contract=state.environment.active_account.contract_name,
            function_name=state.environment.active_function_name,
            address=address,
            swc_id=ASSERT_VIOLATION,
            title="Exception State",
            severity="Low",
            description_head="A reachable exception has been detected.",
            description_tail=description_tail,
            bytecode=state.environment.code.bytecode,
            debug=debug,
            gas_used=(state.mstate.min_gas_used, state.mstate.max_gas_used),
        )
        return [issue]

    except UnsatError:
        log.debug("no model found")

    return []


detector = ArbitraryJumpModule()
