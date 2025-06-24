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

import {IMessageHandler} from "@othentic/NetworkManagement/Common/interfaces/IMessageHandler.sol";
import {IL1AvsTreasury} from "@othentic/NetworkManagement/L1/interfaces/IL1AvsTreasury.sol";
import {IOthenticRegistry} from "@othentic/NetworkManagement/L1/interfaces/IOthenticRegistry.sol";
import {IAvsGovernanceLogic} from "@othentic/NetworkManagement/L1/interfaces/IAvsGovernanceLogic.sol";
import {IAVSDirectory} from "@eigenlayer/contracts/interfaces/IAVSDirectory.sol";
import {IAvsGovernance} from "@othentic/NetworkManagement/L1/interfaces/IAvsGovernance.sol";
import {INetworkRegistry} from "@symbiotic/src/interfaces/INetworkRegistry.sol";
import {INetworkMiddlewareService} from "@symbiotic/src/contracts/service/NetworkMiddlewareService.sol";

struct AvsGovernanceStorageData {
    uint24 slashingRate;
    uint256 numOfActiveOperators;
    IMessageHandler messageHandler;
    IOthenticRegistry othenticRegistry; // Stored on constructor, kept for storage layout compatibility
    IL1AvsTreasury avsTreasury;
    IAVSDirectory avsDirectoryContract;
    bool isAllowlisted;
    address allowlistSigner;
    mapping(address => uint256) isOperatorRegistered; // We are using uint256 for backwards compatibility
    IAvsGovernanceLogic avsGovernanceLogic;
    address[] stakingContracts;
    string avsName;
    uint256 rewardsReceiverModificationDelay;
    mapping(address => bool) isRequestPaymentPaused;
    mapping(address => address) rewardsReceiver;
    mapping(address => IAvsGovernance.RewardsReceiverModificationDetails) rewardsReceiverModificationDetails;
    uint256 numOfOperatorsLimit;
    uint256 minVotingPower;
    uint256 maxEffectiveBalance;
    mapping(address => uint256) minStakeAmountPerStakingContract;
    mapping(address => uint256) multipliers;
    address avsGovernanceMultiplierSyncer;
    address blsAuthSingleton;
    mapping(address => IAvsGovernance.SharedSecurityProvider) stakingContractToSharedSecurityProvider;
    bool p2pAuthenticationEnabled;
}

library AvsGovernanceStorage {
    uint256 private constant STORAGE_POSITION = uint256(keccak256("storage.avs.governance")) - 1;

    function load() internal pure returns (AvsGovernanceStorageData storage sd) {
        uint256 position = STORAGE_POSITION;
        assembly {
            sd.slot := position
        }
    }
}
