// SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.25;

/*______     __      __                              __      __ 
 /      \   /  |    /  |                            /  |    /  |
/$$$$$$  | _$$ |_   $$ |____    ______   _______   _$$ |_   $$/   _______ 
$$ |  $$ |/ $$   |  $$      \  /      \ /       \ / $$   |  /  | /       |
$$ |  $$ |$$$$$$/   $$$$$$$  |/$$$$$$  |$$$$$$$  |$$$$$$/   $$ |/$$$$$$$/ 
$$ |  $$ |  $$ | __ $$ |  $$ |$$    $$ |$$ |  $$ |  $$ | __ $$ |$$ |
$$ \__$$ |  $$ |/  |$$ |  $$ |$$$$$$$$/ $$ |  $$ |  $$ |/  |$$ |$$ \_____ 
$$    $$/   $$  $$/ $$ |  $$ |$$       |$$ |  $$ |  $$  $$/ $$ |$$       |
 $$$$$$/     $$$$/  $$/   $$/  $$$$$$$/ $$/   $$/    $$$$/  $$/  $$$$$$$/
*/
import {IAttestationCenter} from "./IAttestationCenter.sol";
import {IOBLS} from "../../Common/interfaces/IOBLS.sol";

struct VotingPowerUpdate {
    IOBLS.OperatorVotingPower[] toIncrease;
    IOBLS.OperatorVotingPower[] toDecrease;
    uint256 toBlockL1;
    uint256 toBlockL2;
}

struct InternalTransaction {
    address to;
    bytes data;
}

/**
 * @author Othentic Labs LTD.
 * @notice Terms of Service: https://www.othentic.xyz/terms-of-service
 */
interface IInternalTaskHandler {
    event TaskProcessed(uint256 taskDefinitionId, string proofOfTask);
    event VotingPowerUpdated(uint256 toBlockL1, uint256 toBlockL2, string proofOfTask);
    event ExecuteInternalTransactionsTask(InternalTransaction[] transactions);

    error InvalidToBlockL1VsLastCommitBlockL1(uint256 requiredMinToBlockL1);
    error InvalidToBlockL2VsLastCommitBlockL2(uint256 requiredMinToBlockL2);
    error InvalidToBlockL2VsCurrentHeight(uint256 toBlockL2, uint256 currentHeight);
    error InvalidIntenalTransactionNonce(uint256 requiredNonce, uint256 currentNonce);
    error InternalTransactionRevert(bytes reason);
    error InternalTransactionNotAllowed(address to, bytes data);

    function processTask(IAttestationCenter.TaskInfo calldata _task) external;
}
