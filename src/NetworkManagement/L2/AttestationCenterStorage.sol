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

import "@othentic/NetworkManagement/Common/interfaces/IOBLS.sol";
import "@othentic/NetworkManagement/Common/interfaces/IMessageHandler.sol";
import "@othentic/NetworkManagement/L2/interfaces/IAvsLogic.sol";
import "@othentic/NetworkManagement/L2/interfaces/IBeforePaymentsLogic.sol";
import "@othentic/NetworkManagement/L2/TaskDefinitionLibrary.sol";
import "@othentic/NetworkManagement/L2/interfaces/IAttestationCenter.sol";
import "@othentic/NetworkManagement/L2/interfaces/IFeeCalculator.sol";
import "@othentic/NetworkManagement/Common/interfaces/IAvsTreasury.sol";
import "@othentic/NetworkManagement/L2/interfaces/IInternalTaskHandler.sol";

struct AttestationCenterStorageData {
    uint32 taskNumber;
    uint256 baseRewardFee; // @obsolete - default reward fee for attesters is part of defaultTaskDefinition
    uint256 numOfTotalOperators;
    IOBLS obls;
    IMessageHandler messageHandler;
    IAvsLogic avsLogic;
    TaskDefinitions taskDefinitions;
    mapping(bytes32 => bool) signedTasks;
    mapping(address => uint256) operatorsIdsByAddress;
    mapping(uint256 => IAttestationCenter.PaymentDetails) operators;
    uint256 numOfActiveOperators;
    IFeeCalculator feeCalculator;
    mapping(address => address) rewardsReceiver;
    bool isRewardsOnL2;
    IAvsTreasury avsTreasury;
    IBeforePaymentsLogic beforePaymentsLogic;
    IInternalTaskHandler internalTaskHandler;
    bool isOpenAggregator;
    uint256 nextEigenRewardsBatchStartTimestamp;
}

library AttestationCenterStorage {
    uint256 private constant STORAGE_POSITION = uint256(keccak256("storage.attestation.center")) - 1;

    function load() internal pure returns (AttestationCenterStorageData storage sd) {
        uint256 position = STORAGE_POSITION;
        assembly {
            sd.slot := position
        }
    }
}
