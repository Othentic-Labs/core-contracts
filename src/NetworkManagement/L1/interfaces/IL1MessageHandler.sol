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

import "@othentic/NetworkManagement/L1/interfaces/IAvsGovernanceExtension.sol";
import {IRewardsCoordinator} from "@eigenlayer/contracts/interfaces/IRewardsCoordinator.sol";

/**
 * @author Othentic Labs LTD.
 * @notice Terms of Service: https://www.othentic.xyz/terms-of-service
 */
interface IL1MessageHandler {
    event OperatorEjectionRequested(address operator);
    event PaymentRequested(address operator, uint256 lastPaidTaskNumber, uint256 feeToClaim);
    event PaymentsRequested(IAvsGovernanceExtension.PaymentRequestMessage[] operator, uint256 lastPaidTaskNumber);
    event EigenPaymentsRequested(IRewardsCoordinator.OperatorReward[] operator, uint256 lastPaidTaskNumber);
    event SetAvsGovernance(address avsGovernance);
    event NewSupportedL2(uint32 lzEid);

    error L2AlreadySupported(uint32 lzEid);

    function setAvsGovernance(address _avsGovernance) external;
}
