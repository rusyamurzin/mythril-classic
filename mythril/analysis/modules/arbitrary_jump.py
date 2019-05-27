import logging
import json

from mythril.analysis import solver
from mythril.analysis.modules.base import DetectionModule
from mythril.analysis.report import Issue
from mythril.analysis.swc_data import ARBITRARY_JUMP
from mythril.exceptions import UnsatError
from mythril.laser.ethereum import util
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
            pre_hooks=["MSTORE", "CREATE"],
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
    log.info("Arbitrary jump module: found MSTORE or CREATE instruction")

    try:
        instruction = state.get_current_instruction()
        address = instruction["address"]
        description_tail = (
            "The use of assembly is error-prone and should be avoided."
            "Usage MSTORE instruction or assign operator in assembly block"
            "is able to point a function type variable to any code instruction."
        )

        op_code = state.get_current_instruction()["opcode"]
        func_name = state.environment.active_function_name
        #May be func_name check is reduntant
        if op_code in "MSTORE" and func_name.upper() in "ASSEMBLY":
            log.debug("ASSEMBLY usage in function " + func_name)
            op0 = state.mstate.stack[-1]
            disassembly = state.environment.code
            #Check first argument of MSTORE to a function type
            try:
                jump_addr = util.get_concrete_int(op0)
            except TypeError:
                log.debug("MSTORE argument is not a function")
                return []

            index = util.get_instruction_index(disassembly.instruction_list, jump_addr)
            if index is None:
                log.debug("MSTORE argument is not a function")
                return []

            dest_op_code = disassembly.instruction_list[index]["opcode"]

            #if first argument of MSTORE is a function type
            if dest_op_code == "JUMPDEST":
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
