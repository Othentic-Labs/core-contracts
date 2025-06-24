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

import {IAvsGovernanceLogic} from "@othentic/NetworkManagement/L1/interfaces/IAvsGovernanceLogic.sol";
import {ISignatureUtils} from "@eigenlayer/contracts/interfaces/ISignatureUtils.sol";
import {BLSAuthLibrary} from "@othentic/NetworkManagement/Common/BLSAuthLibrary.sol";
import {IOthenticRegistry} from "@othentic/NetworkManagement/L1/interfaces/IOthenticRegistry.sol";

interface IAvsGovernanceExtension {
    struct PaymentRequestMessage {
        address operator;
        uint256 feeToClaim;
    }

    event QueuedRewardsReceiverModification(address indexed operator, address receiver, uint256 delay);
    event MinStakeForStakingContractSet(address stakingContract, uint256 minShares);
    event SetAvsGovernanceMultiplierSyncer(address avsGovernanceMultiplierSyncer);
    event SetRewardsReceiverModificationDelay(uint256 modificationDelay);
    event SetAvsGovernanceMultisig(address newAvsGovernanceMultisig);
    event SetNumOfOperatorsLimit(uint256 newLimitOfNumOfOperators);
    event MaxEffectiveBalanceSet(uint256 maxEffectiveBalance);
    event SetAvsGovernanceLogic(address avsGovernanceLogic);
    event BLSAuthSingletonSet(address blsAuthSingleton);
    event SetMessageHandler(address newMessageHandler);
    event SetAllowlistSigner(address allowlistSigner);
    event MinVotingPowerSet(uint256 minVotingPower);
    event SetIsAllowlisted(bool isAllowlisted);

    event FundsRescued(address token, address caller, uint256 amount);

    error NumOfActiveOperatorsIsGreaterThanNumOfOperatorLimit(uint256 numOfOperatorsLimit, uint256 numOfActiveOperators);
    error OperatorAlreadyRegistered();
    error InvalidStakingContract();
    error InvalidRewardsReceiver();
    error OperatorNotRegistered();
    error ZeroAddress();

    // -------------------- Layer 2 Interface -------------------- //
    function withdrawBatchRewards(PaymentRequestMessage[] memory _operators, uint256 _lastPayedTask, uint32 _remoteId)
        external;

    // -------------------- AvsGovernance Multisig Interface -------------------- //
    function setNumOfOperatorsLimit(uint256 newLimitOfNumOfOperators) external;
    function setIsAllowlisted(bool) external;
    function setAvsGovernanceLogic(IAvsGovernanceLogic _avsGovernanceLogic) external;
    function setAvsGovernanceMultiplierSyncer(address) external;
    function setMaxEffectiveBalance(uint256) external;
    function setMinStakesForStakingContract(address, uint256) external;
    function setMinVotingPower(uint256) external;
    function transferAvsGovernanceMultisig(address _newAvsGovernanceMultisig) external;
    function rescueFunds() external;

    // -------------------- Avs Governance Multiplier Syncer Interface -------------------- ///
    function setRewardsReceiverModificationDelay(uint256 _rewardsReceiverModificationDelay) external;

    // -------------------- Operations Multisig Interface -------------------- //
    function transferMessageHandler(address) external;
    function setBLSAuthSingleton(address) external;
    function setAllowlistSigner(address) external;

    // -------------------- IServiceManager Interface -------------------- //
    function avsDirectory() external view returns (address);

    // -------------------- AvsGovernance configuration Interface -------------------- //
    function getNumOfOperatorsLimit() external view returns (uint256 numOfOperatorsLimitView);
    function getL1MessageHandler() external view returns (address);
}
