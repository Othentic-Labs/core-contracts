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

import {ISignatureUtils} from "@eigenlayer/contracts/interfaces/ISignatureUtils.sol";
import {BLSAuthLibrary} from "@othentic/NetworkManagement/Common/BLSAuthLibrary.sol";
import {IAccessControl} from "openzeppelin-contracts/contracts/access/IAccessControl.sol";
import {IRewardsCoordinator} from "@eigenlayer/contracts/interfaces/IRewardsCoordinator.sol";

/**
 * @author Othentic Labs LTD.
 * @notice Terms of Service: https://www.othentic.xyz/terms-of-service
 */
interface IAvsGovernance is IAccessControl {
    enum SharedSecurityProvider {
        EigenLayer,
        Symbiotic
    }

    struct StakingContractInfo {
        address stakingContract;
        SharedSecurityProvider sharedSecurityProvider;
    }

    struct VotingPowerMultiplier {
        address stakingContract;
        uint256 multiplier;
        SharedSecurityProvider sharedSecurityProvider;
    }

    struct StakingContractDetails {
        address stakingContract;
        uint256 stakeAmount;
        SharedSecurityProvider sharedSecurityProvider;
    }

    struct StakingContractMinStakeInfo {
        address stakingContract;
        uint256 minStakeAmount;
    }

    struct Operator {
        uint256[4] blsKey;
        uint256 stake;
        bool isAllowlisted;
        bool isActive;
    }

    struct EigenRewardsSubmissionData {
        uint32 startTimestamp;
        uint32 duration;
        uint256 totalRewards;
        uint256 operatorCount;
    }

    struct RewardsReceiverModificationDetails {
        address newRewardsReceiver;
        uint256 modificationDelay;
    }

    struct InitializationParams {
        address avsGovernanceMultisigOwner;
        address operationsMultisig;
        address communityMultisig;
        address othenticRegistry;
        address messageHandler;
        address avsTreasury;
        address avsDirectoryContract;
        address allowlistSigner;
        string avsName;
        address blsAuthSingleton;
    }

    struct OperatorRegistrationParams {
        uint256[4] blsKey;
        address rewardsReceiver;
        BLSAuthLibrary.Signature blsRegistrationSignature;
        bytes authToken;
    }

    struct SharedSecurityProviderSignature {
        SharedSecurityProvider provider;
        bytes data;
    }

    struct SymbioticOptInSignature {
        uint48 deadline;
        bytes data;
    }

    struct SymbioticOptOutSignature {
        uint48 deadline;
        bytes data;
    }

    // Events
    event SetToken(address token);
    event SetAvsName(string avsName);
    event SetIsAllowlisted(bool isAllowlisted);
    event setNewSupportedStakingContracts(address[] stakingContracts);
    event QueuedRewardsReceiverModification(address indexed operator, address receiver, uint256 delay);
    event SetRewardsReceiver(address indexed operator, address receiver);
    event OperatorRegistered(address indexed operator, uint256[4] blsKey);
    event OperatorUnregistered(address indexed operator);
    event SetStakingContractMultiplier(address stakingContract, uint256 multiplier);
    event OperatorRegisteredToEigenLayer(address operator);
    event OperatorRegisteredToSymbiotic(address operator);
    event OperatorUnregisteredToSymbiotic(address operator);
    event NativeCoinNotSupportedForEigenRewards();
    event RewardsCoordinatorReverted(bytes revertData);
    event OperatorUnregisteredToEigenLayer(address operator);
    event OperatorEjectedFromNetwork(address operator);
    event DepositRewardsBackFailed();
    event SetP2pAuthenticationEnabled(bool _isEnabled);

    // Errors
    error ZeroAddress();
    error Unauthorized(string message);
    error NumOfOperatorsLimitReached(uint256 numOfOperatorsLimit);
    error OperatorNotRegistered();
    error OperatorAlreadyRegistered();
    error InvalidBlsRegistrationSignature();
    error InvalidRewardsReceiver();
    error AllowlistDisabled();
    error AllowlistEnabled();
    error InvalidAllowlistAuthToken();
    error ModificationDelayNotPassed();
    error InvalidSlashingRate();
    error InvalidStakingContract();
    error AccessControlInvalidMultiplierSyncer();
    error InvalidMultiplierNotSet();
    error NotEnoughVotingPower();
    error MissingAuthToken(bytes);
    error EmptySharedSecurityProvidersList();
    error InvalidSharedSecurityProviderList(uint256 arrayIndex);
    error OperatorStillRegisteredToSharedSecurityProviders(address operator);
    error EmptyAvsName();
    error StakingContractsNotInAscendingOrder();
    error InvalidMultiplier();
    error TreasuryWithdrawRewardsFailed();
    error NativeCoinNotSupportedForEigenRewardsError();
    
    // Functions

    /// @dev See extension contract for additional available methods implemented on AvsGovernanceExtension.sol
    function EXTENSION_IMPLEMENTATION() external view returns (address);

    // -------------------- Operators Interface -------------------- //
    function avsTreasury() external view returns (address);
    function getIsAllowlisted() external view returns (bool);
    function avsName() external view returns (string memory);
    function minStakeAmountPerStakingContract(address) external view returns (uint256);
    function minVotingPower() external view returns (uint256);
    function maxEffectiveBalance() external view returns (uint256);
    function stakingContracts() external view returns (address[] memory);
    function multiplier(address) external view returns (uint256);
    function getRewardsReceiver(address) external view returns (address);
    function registerAsOperator(OperatorRegistrationParams calldata _operatorRegistrationParams) external;
    function unregisterAsOperatorFromEigenLayer() external;
    function queueRewardsReceiverModification(address _rewardsReceiver) external;
    function completeRewardsReceiverModification() external;
    function votingPower(address _operator) external view returns (uint256);
    function votingPowerPerStakingContracts(address _operator, address[] calldata _stakingContracts)
        external
        view
        returns (uint256);

    // -------------------- Layer 2 Interface -------------------- //
    function isOperatorRegistered(address operator) external view returns (bool);
    function numOfActiveOperators() external view returns (uint256);
    function ejectOperatorFromNetwork(address _operator) external;
    function createOperatorDirectedAVSRewardsSubmission(
        IRewardsCoordinator.OperatorReward[] memory _operators,
        uint256 _lastPayedTask,
        bytes memory _data,
        uint32 _remoteId
    ) external;

    // -------------------- AvsGovernance Multisig Interface -------------------- //
    function setSupportedStakingContracts(StakingContractInfo[] memory _stakingContractsDetails) external;
    function setP2pAuthenticationEnabled(bool _p2pAuthenticationEnabled) external;

    // -------------------- IServiceManager Interface -------------------- //
    function getOperatorRestakedStrategies(address operator) external view returns (address[] memory);
    function getRestakeableStrategies() external view returns (address[] memory);

    // -------------------- Register AVS to shared security provider -------------------- //
    function registerAvsToEigenLayer(string calldata metadataURI) external;
    function registerAvsToSymbiotic() external;

    // -------------------- Register Operator to shared security provider -------------------- //
    function registerOperatorToEigenLayer(
        ISignatureUtils.SignatureWithSaltAndExpiry memory _eigenSig,
        bytes calldata _authToken
    ) external;
    function registerOperatorToSymbiotic(SymbioticOptInSignature memory _symbioticSig, bytes calldata _authToken)
        external;
}
