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

import {AccessControlUpgradeable} from
    "openzeppelin-contracts-upgradeable/contracts/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from
    "openzeppelin-contracts-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IMessageHandler} from "@othentic/NetworkManagement/Common/interfaces/IMessageHandler.sol";
import {IAvsGovernance} from "@othentic/NetworkManagement/L1/interfaces/IAvsGovernance.sol";
import {IOthenticRegistry} from "@othentic/NetworkManagement/L1/interfaces/IOthenticRegistry.sol";
import {IL1AvsTreasury} from "@othentic/NetworkManagement/L1/interfaces/IL1AvsTreasury.sol";
import {AvsGovernancePausable} from "@othentic/NetworkManagement/L1/AvsGovernancePausable.sol";
import {ISignatureUtils} from "@eigenlayer/contracts/interfaces/ISignatureUtils.sol";
import {IRewardsCoordinator} from "@eigenlayer/contracts/interfaces/IRewardsCoordinator.sol";
import {IStrategy} from "@eigenlayer/contracts/interfaces/IStrategy.sol";
import {AvsGovernanceStorage, AvsGovernanceStorageData} from "@othentic/NetworkManagement/L1/AvsGovernanceStorage.sol";
import {L1AvsTreasury} from "@othentic/NetworkManagement/L1/L1AvsTreasury.sol";
import {IAvsGovernanceLogic} from "@othentic/NetworkManagement/L1/interfaces/IAvsGovernanceLogic.sol";
import {MessagesLibrary} from "@othentic/NetworkManagement/Common/MessagesLibrary.sol";
import {RolesLibrary} from "@othentic/NetworkManagement/Common/RolesLibrary.sol";
import {PauserRolesLibrary} from "@othentic/NetworkManagement/Common/PauserRolesLibrary.sol";
import {SignedAuthTokenLibrary} from "@othentic/NetworkManagement/Common/SignedAuthTokenLibrary.sol";
import {BLSAuthLibrary} from "@othentic/NetworkManagement/Common/BLSAuthLibrary.sol";
import {IBLSAuthSingleton} from "@othentic/NetworkManagement/Common/interfaces/IBLSAuthSingleton.sol";
import {IAVSDirectory} from "@eigenlayer/contracts/interfaces/IAVSDirectory.sol";
import {INetworkRegistry} from "@symbiotic/src/interfaces/INetworkRegistry.sol";
import {IBaseDelegator} from "@symbiotic/src/interfaces/delegator/IBaseDelegator.sol";
import {IOptInService} from "@symbiotic/src/interfaces/service/IOptInService.sol";
import {IVaultStorage} from "@symbiotic/src/interfaces/vault/IVaultStorage.sol";
import {IAVSDirectoryFull} from "@othentic/NetworkManagement/L1/interfaces/IAVSDirectoryFull.sol";
import {SafeERC20NoRevert} from "@othentic/NetworkManagement/Common/SafeERC20NoRevert.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @author Othentic Labs LTD.
 * @notice Terms of Service: https://www.othentic.xyz/terms-of-service
 */
contract AvsGovernance is IAvsGovernance, AvsGovernancePausable, ReentrancyGuardUpgradeable {
    using SafeERC20 for IERC20;
    using SafeERC20NoRevert for IERC20;

    address public immutable EXTENSION_IMPLEMENTATION;
    IOthenticRegistry private immutable OTHENTIC_REGISTRY;

    using SignedAuthTokenLibrary for bytes;

    // MODIFIERS
    modifier onlyRegisteredOperator() {
        if (_getStorage().isOperatorRegistered[msg.sender] == 0) revert OperatorNotRegistered();
        _;
    }

    modifier onlyUnregisteredOperator() {
        if (_getStorage().isOperatorRegistered[msg.sender] != 0) revert OperatorAlreadyRegistered();
        _;
    }

    fallback() external {
        _delegate(EXTENSION_IMPLEMENTATION);
    }

    constructor(address _extensionImplementation, IOthenticRegistry _othenticRegistryAddress) {
        if (_extensionImplementation == address(0) || address(_othenticRegistryAddress) == address(0)) {
            revert ZeroAddress();
        }
        EXTENSION_IMPLEMENTATION = _extensionImplementation;
        OTHENTIC_REGISTRY = _othenticRegistryAddress;
    }

    // EXTERNAL FUNCTIONS
    function initialize(InitializationParams calldata _initializationParams) public virtual initializer {
        _initialize(_initializationParams);
    }

    function _initialize(InitializationParams calldata _initializationParams) internal onlyInitializing {
        if (
            _initializationParams.avsGovernanceMultisigOwner == address(0)
                || _initializationParams.operationsMultisig == address(0)
                || _initializationParams.communityMultisig == address(0)
                || _initializationParams.messageHandler == address(0) || _initializationParams.avsTreasury == address(0)
                || _initializationParams.avsDirectoryContract == address(0)
                || _initializationParams.allowlistSigner == address(0)
                || _initializationParams.blsAuthSingleton == address(0)
        ) {
            revert ZeroAddress();
        }
        address _avsGovernanceMultisigOwner = _initializationParams.avsGovernanceMultisigOwner;
        address _operationsMultisig = _initializationParams.operationsMultisig;
        address _communityMultisig = _initializationParams.communityMultisig;
        address _messageHandler = _initializationParams.messageHandler;
        string calldata _avsName = _initializationParams.avsName;
        __OthenticAccessControl_init(_avsGovernanceMultisigOwner, _operationsMultisig, _communityMultisig);
        __AvsGovernancePausable_init(_avsGovernanceMultisigOwner, _operationsMultisig, _communityMultisig);
        __ReentrancyGuard_init();
        AvsGovernanceStorageData storage _sd = _getStorage();
        _sd.messageHandler = IMessageHandler(_messageHandler);
        _grantRole(RolesLibrary.MESSAGE_HANDLER, _messageHandler);
        _sd.avsTreasury = IL1AvsTreasury(_initializationParams.avsTreasury);
        _sd.allowlistSigner = _initializationParams.allowlistSigner;
        _sd.rewardsReceiverModificationDelay = 7 days;
        _sd.avsDirectoryContract = IAVSDirectory(_initializationParams.avsDirectoryContract);
        _sd.numOfOperatorsLimit = 100;
        _sd.blsAuthSingleton = _initializationParams.blsAuthSingleton;
        _setAvsName(_sd, _avsName);
        OTHENTIC_REGISTRY.registerAvs(_avsName);
        _setSupportedStakingContracts(_sd, _getDefaultStrategies());
    }

    // -------------------- Operators Interface -------------------- //
    function registerAsOperator(OperatorRegistrationParams calldata _operatorRegistrationParams)
        external
        onlyUnregisteredOperator
        whenFlowNotPaused(PauserRolesLibrary.REGISTRATION_FLOW)
        nonReentrant
    {
        AvsGovernanceStorageData storage _sd = _getStorage();
        _verifyAuthToken(_sd, _operatorRegistrationParams.authToken);
        _registerAsOperator(
            _sd,
            msg.sender,
            _operatorRegistrationParams.blsKey,
            _operatorRegistrationParams.blsRegistrationSignature,
            _operatorRegistrationParams.rewardsReceiver
        );
    }

    function unregisterAsOperatorFromSymbiotic(SymbioticOptOutSignature calldata _unregistrationSignature)
        external
        onlyRegisteredOperator
        whenFlowNotPaused(PauserRolesLibrary.REGISTRATION_FLOW)
        nonReentrant
    {
        OTHENTIC_REGISTRY.optInService().optOut(
            msg.sender, address(this), _unregistrationSignature.deadline, _unregistrationSignature.data
        );
        emit OperatorUnregisteredToSymbiotic(msg.sender);
    }

    function unregisterAsOperatorFromEigenLayer()
        external
        onlyRegisteredOperator
        whenFlowNotPaused(PauserRolesLibrary.REGISTRATION_FLOW)
        nonReentrant
    {
        _getStorage().avsDirectoryContract.deregisterOperatorFromAVS(msg.sender);
        emit OperatorUnregisteredToEigenLayer(msg.sender);
    }

    function unregisterAsOperatorFromAvs()
        external
        onlyRegisteredOperator
        whenFlowNotPaused(PauserRolesLibrary.REGISTRATION_FLOW)
        nonReentrant
    {
        AvsGovernanceStorageData storage _sd = _getStorage();
        if (
            (
                IAVSDirectoryFull(address(_sd.avsDirectoryContract)).avsOperatorStatus(address(this), msg.sender)
                    != IAVSDirectory.OperatorAVSRegistrationStatus.REGISTERED
            ) && !OTHENTIC_REGISTRY.optInService().isOptedIn(msg.sender, address(this))
        ) {
            IAvsGovernanceLogic _avsGovernanceLogic = _sd.avsGovernanceLogic;
            bool _isAvsGovernanceLogicSet = address(_avsGovernanceLogic) != address(0);
            if (_isAvsGovernanceLogicSet) {
                _avsGovernanceLogic.beforeOperatorUnregistered(msg.sender);
            }
            _unregisterAsOperator(_sd, msg.sender);
            if (_isAvsGovernanceLogicSet) {
                _avsGovernanceLogic.afterOperatorUnregistered(msg.sender);
            }
        } else {
            revert OperatorStillRegisteredToSharedSecurityProviders(msg.sender);
        }
    }

    function getIsAllowlisted() external view returns (bool) {
        return _getStorage().isAllowlisted;
    }

    function avsName() external view returns (string memory) {
        return _getStorage().avsName;
    }

    function avsTreasury() external view returns (address) {
        return address(_getStorage().avsTreasury);
    }

    function minStakeAmountPerStakingContract(address _stakingContract) external view returns (uint256) {
        return _getStorage().minStakeAmountPerStakingContract[_stakingContract];
    }

    function minVotingPower() external view returns (uint256) {
        return _getStorage().minVotingPower;
    }

    function maxEffectiveBalance() external view returns (uint256) {
        return _getStorage().maxEffectiveBalance;
    }

    function stakingContracts() external view returns (address[] memory) {
        return _getStorage().stakingContracts;
    }

    function multiplier(address _stakingContract) external view returns (uint256) {
        return _getStorage().multipliers[_stakingContract];
    }

    function p2pAuthenticationEnabled() external view returns (bool) {
        return _getStorage().p2pAuthenticationEnabled;
    }

    function getRewardsReceiver(address _operator) external view returns (address) {
        return _getStorage().rewardsReceiver[_operator];
    }
    // only supported on L1

    function queueRewardsReceiverModification(address _newRewardsReceiver)
        external
        onlyRegisteredOperator
        whenFlowNotPaused(PauserRolesLibrary.OPERATOR_SET_REWARDS_RECEIVER_FLOW)
    {
        if (_newRewardsReceiver == address(0)) revert InvalidRewardsReceiver();
        AvsGovernanceStorageData storage _sd = _getStorage();
        _sd.isRequestPaymentPaused[msg.sender] = true;
        uint256 _modificationDelay = block.timestamp + _sd.rewardsReceiverModificationDelay;
        _sd.rewardsReceiverModificationDetails[msg.sender] =
            RewardsReceiverModificationDetails(_newRewardsReceiver, _modificationDelay);
        emit QueuedRewardsReceiverModification(msg.sender, _newRewardsReceiver, _modificationDelay);
    }

    function completeRewardsReceiverModification() external onlyRegisteredOperator {
        AvsGovernanceStorageData storage _sd = _getStorage();
        if (block.timestamp < _sd.rewardsReceiverModificationDetails[msg.sender].modificationDelay) {
            revert ModificationDelayNotPassed();
        }
        _setRewardsReceiver(_sd, _sd.rewardsReceiverModificationDetails[msg.sender].newRewardsReceiver);
        _sd.isRequestPaymentPaused[msg.sender] = false;
        _sd.rewardsReceiverModificationDetails[msg.sender] = RewardsReceiverModificationDetails(address(0), 0);
    }

    function votingPower(address _operator) external view returns (uint256) {
        AvsGovernanceStorageData storage _sd = _getStorage();
        (, IAvsGovernance.VotingPowerMultiplier[] memory _votingPowerMultipliers) =
            _calculateStakingContractDetailsAndMultipliers(_sd, _sd.stakingContracts);
        return _getVotingPower(_sd, _operator, _votingPowerMultipliers);
    }

    function votingPowerPerStakingContracts(address _operator, address[] calldata _stakingContracts)
        external
        view
        returns (uint256)
    {
        AvsGovernanceStorageData storage _sd = _getStorage();
        (, IAvsGovernance.VotingPowerMultiplier[] memory _votingPowerMultipliers) =
            _calculateStakingContractDetailsAndMultipliers(_sd, _stakingContracts);
        return _getVotingPower(_sd, _operator, _votingPowerMultipliers);
    }

    // -------------------- Layer 2 Interface -------------------- //

    /// @dev Can only be called by AttestationCenter::requestPayment using MessageHandler, pauseFlow protection is enforced on AttestationCenter.

    function isOperatorRegistered(address operator) external view returns (bool) {
        return _getStorage().isOperatorRegistered[operator] != 0;
    }

    function numOfActiveOperators() external view returns (uint256) {
        return _getStorage().numOfActiveOperators;
    }

    /// @dev Can only be called by AttestationCenter::ejectOperatorFromNetwork using MessageHandler
    function ejectOperatorFromNetwork(address _operator) external nonReentrant onlyRole(RolesLibrary.MESSAGE_HANDLER) {
        AvsGovernanceStorageData storage _sd = _getStorage();
        if (
            IAVSDirectoryFull(address(_sd.avsDirectoryContract)).avsOperatorStatus(address(this), _operator)
                == IAVSDirectory.OperatorAVSRegistrationStatus.REGISTERED
        ) {
            _sd.avsDirectoryContract.deregisterOperatorFromAVS(_operator);
            emit OperatorUnregisteredToEigenLayer(_operator);
        }
        _unregisterAsOperator(_sd, _operator);

        emit OperatorEjectedFromNetwork(_operator);
    }

    /// @dev This flow is on L1 only.Add commentMore actions
    function createEigenRewardsSubmission(uint32 _startTimestamp, uint32 _duration, uint256 _amount)
        external
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
    {
        AvsGovernanceStorageData storage _sd = _getStorage();
        IL1AvsTreasury _avsTreasury = _sd.avsTreasury;
        IRewardsCoordinator _rewardsCoordinator = OTHENTIC_REGISTRY.rewardsCoordinator();
        address _token = _sd.avsTreasury.getToken();

        if (_token == _sd.avsTreasury.ETH_ADDRESS()) {
            revert NativeCoinNotSupportedForEigenRewardsError();
        }

        if (!_withdrawRewards(address(this), address(this), 0, _amount, _avsTreasury)) {
            revert TreasuryWithdrawRewardsFailed();
        }
        IERC20(_token).safeIncreaseAllowance(address(_rewardsCoordinator), _amount);

        IRewardsCoordinator.RewardsSubmission[] memory _submissions =
            new IRewardsCoordinator.RewardsSubmission[](1);
        _submissions[0] = IRewardsCoordinator.RewardsSubmission({
            strategiesAndMultipliers: _buildStrategyAndMultipliers(_sd),
            token: IERC20(_token),
            amount: _amount,
            startTimestamp: _startTimestamp,
            duration: _duration
        });

        _rewardsCoordinator.createAVSRewardsSubmission(_submissions);
    }    

    /// @dev Can only be called by AttestationCenter::requestPayment using MessageHandler, pauseFlow protection is enforced on AttestationCenter.
    function createOperatorDirectedAVSRewardsSubmission(
        IRewardsCoordinator.OperatorReward[] memory _operators,
        uint256 _lastPayedTask,
        bytes memory _rewardsData,
        uint32 _remoteEid
    ) external onlyRole(RolesLibrary.MESSAGE_HANDLER) {
        AvsGovernanceStorageData storage _sd = _getStorage();
        IL1AvsTreasury _avsTreasury = _sd.avsTreasury;
        IRewardsCoordinator _rewardsCoordinator = OTHENTIC_REGISTRY.rewardsCoordinator();
        EigenRewardsSubmissionData memory _eigenRewardsSubmissionData;
        (
            _eigenRewardsSubmissionData.startTimestamp,
            _eigenRewardsSubmissionData.duration,
            _eigenRewardsSubmissionData.totalRewards,
            _eigenRewardsSubmissionData.operatorCount
        ) = abi.decode(_rewardsData, (uint32, uint32, uint256, uint256));

        address _token = _sd.avsTreasury.getToken();
        bool _success = false;
        bytes memory _revertData;

        if (_token != _sd.avsTreasury.ETH_ADDRESS()) {
            _success = _withdrawRewards(
                address(this), address(this), _lastPayedTask, _eigenRewardsSubmissionData.totalRewards, _avsTreasury
            );

            if (_success) {
                IERC20(_token).safeIncreaseAllowanceNoRevert(
                    address(_rewardsCoordinator), _eigenRewardsSubmissionData.totalRewards
                );
                (_success, _revertData) = address(_rewardsCoordinator).call(
                    abi.encodeWithSelector(
                        IRewardsCoordinator.createOperatorDirectedAVSRewardsSubmission.selector,
                        address(this),
                        _buildRewardsSubmission(
                            _operators,
                            _eigenRewardsSubmissionData.startTimestamp,
                            _eigenRewardsSubmissionData.duration,
                            _token
                        )
                    )
                );
                if (!_success) {
                    IERC20(_token).safeIncreaseAllowanceNoRevert(
                        address(_avsTreasury), _eigenRewardsSubmissionData.totalRewards
                    );
                    bool depositSuccess = _avsTreasury.depositERC20RewardsBack(_eigenRewardsSubmissionData.totalRewards);
                    if (!depositSuccess) {
                        emit DepositRewardsBackFailed();
                    }
                }
            }
        } else {
            emit NativeCoinNotSupportedForEigenRewards();
        }

        if (!_success) {
            for (uint256 i = 0; i < _eigenRewardsSubmissionData.operatorCount; i++) {
                _operators[i].amount = 0;
            }
            emit RewardsCoordinatorReverted(_revertData);
        }
        _triggerL2BatchClearance(_sd, abi.encode(_operators), _lastPayedTask, _remoteEid);
    }

    // -------------------- AvsGovernance Multisig Interface -------------------- //

    function setSupportedStakingContracts(IAvsGovernance.StakingContractInfo[] memory _stakingContractsDetails)
        external
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
        whenFlowNotPaused(PauserRolesLibrary.SET_SUPPORTED_STRATEGIES_FLOW)
    {
        _setSupportedStakingContracts(_getStorage(), _stakingContractsDetails);
    }

    function setP2pAuthenticationEnabled(bool _p2pAuthenticationEnabled)
        external
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
    {
        emit SetP2pAuthenticationEnabled(_p2pAuthenticationEnabled);
        _getStorage().p2pAuthenticationEnabled = _p2pAuthenticationEnabled;
    }

    // -------------------- Avs Governance Multiplier Syncer Interface -------------------- ///
    function setStakingContractMultiplier(VotingPowerMultiplier calldata _votingPowerMultiplier)
        external
        onlyRole(RolesLibrary.MULTIPLIER_SYNCER)
    {
        _setStakingContractMultiplier(_getStorage(), _votingPowerMultiplier);
    }

    function setStakingContractMultiplierBatch(VotingPowerMultiplier[] calldata _votingPowerMultipliers)
        external
        onlyRole(RolesLibrary.MULTIPLIER_SYNCER)
    {
        AvsGovernanceStorageData storage _sd = _getStorage();
        for (uint256 i = 0; i < _votingPowerMultipliers.length;) {
            _setStakingContractMultiplier(_sd, _votingPowerMultipliers[i]);
            unchecked {
                ++i;
            }
        }
    }

    // -------------------- IServiceManager Interface -------------------- //
    function getOperatorRestakedStrategies(address _operator) external view returns (address[] memory) {
        return OTHENTIC_REGISTRY.getOperatorRestakedStrategies(_operator, _getEigenStrategies(), address(this));
    }

    function getRestakeableStrategies() external view returns (address[] memory) {
        return _getEigenStrategies();
    }

    // -------------------- Register AVS to shared security provider -------------------- //
    function registerAvsToEigenLayer(string calldata metadataURI)
        external
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
    {
        _getStorage().avsDirectoryContract.updateAVSMetadataURI(metadataURI);
    }

    function registerAvsToSymbiotic() external onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG) {
        OTHENTIC_REGISTRY.networkRegistry().registerNetwork();
        OTHENTIC_REGISTRY.networkMiddlewareService().setMiddleware(address(this));
    }

    // -------------------- Register Operator to shared security provider -------------------- //
    function registerOperatorToEigenLayer(
        ISignatureUtils.SignatureWithSaltAndExpiry memory _eigenSig,
        bytes calldata _authToken
    ) external {
        AvsGovernanceStorageData storage _sd = _getStorage();
        _verifyAuthToken(_sd, _authToken);
        _registerOperatorToEigenLayer(_getStorage(), msg.sender, _eigenSig);
    }

    function registerOperatorToSymbiotic(SymbioticOptInSignature memory _symbioticSig, bytes calldata _authToken)
        external
    {
        AvsGovernanceStorageData storage _sd = _getStorage();
        _verifyAuthToken(_sd, _authToken);
        _registerOperatorToSymbiotic(msg.sender, _symbioticSig);
    }

    // =============================================================== //

    // INTERNAL FUNCTIONS

    function _getStorage() internal pure returns (AvsGovernanceStorageData storage _sd) {
        return AvsGovernanceStorage.load();
    }

    function _calculateStakingContractDetailsAndMultipliers(
        AvsGovernanceStorageData storage _sd,
        address[] memory _stakingContracts
    )
        internal
        view
        returns (IAvsGovernance.StakingContractDetails[] memory, IAvsGovernance.VotingPowerMultiplier[] memory)
    {
        IAvsGovernance.StakingContractDetails[] memory _minStakeAmountPerStakingContract =
            new IAvsGovernance.StakingContractDetails[](_stakingContracts.length);
        IAvsGovernance.VotingPowerMultiplier[] memory _votingPowerMultipliers =
            new IAvsGovernance.VotingPowerMultiplier[](_stakingContracts.length);

        for (uint256 i = 0; i < _stakingContracts.length;) {
            address _stakingContract = _stakingContracts[i];
            IAvsGovernance.SharedSecurityProvider _sharedSecurityProvider =
                _sd.stakingContractToSharedSecurityProvider[_stakingContract];
            _minStakeAmountPerStakingContract[i] = IAvsGovernance.StakingContractDetails(
                _stakingContract, _sd.minStakeAmountPerStakingContract[_stakingContract], _sharedSecurityProvider
            );
            uint256 _multiplier = _sd.multipliers[_stakingContract];
            if (_multiplier == 0) {
                _multiplier = 1;
            }
            _votingPowerMultipliers[i] =
                IAvsGovernance.VotingPowerMultiplier(_stakingContract, _multiplier, _sharedSecurityProvider);
            unchecked {
                ++i;
            }
        }
        return (_minStakeAmountPerStakingContract, _votingPowerMultipliers);
    }

    function _buildStrategyAndMultipliers(AvsGovernanceStorageData storage _sd)
        internal
        view
        returns (IRewardsCoordinator.StrategyAndMultiplier[] memory)
    {
        (, IAvsGovernance.VotingPowerMultiplier[] memory _votingPowerMultipliers) =
            _calculateStakingContractDetailsAndMultipliers(_sd, _sd.stakingContracts);

        uint256 _eigenStrategyCount = 0;
        IRewardsCoordinator.StrategyAndMultiplier[] memory _strategyMultipliers =
            new IRewardsCoordinator.StrategyAndMultiplier[](_votingPowerMultipliers.length);

        for (uint256 i = 0; i < _votingPowerMultipliers.length; i++) {
            if (_votingPowerMultipliers[i].sharedSecurityProvider == SharedSecurityProvider.EigenLayer) {
                _strategyMultipliers[_eigenStrategyCount++] = IRewardsCoordinator.StrategyAndMultiplier({
                    strategy: IStrategy(_votingPowerMultipliers[i].stakingContract),
                    multiplier: uint96(_votingPowerMultipliers[i].multiplier)
                });
            }
        }
        assembly {
            mstore(_strategyMultipliers, _eigenStrategyCount)
        }
        return _strategyMultipliers;
    }    

    function _verifyAuthToken(AvsGovernanceStorageData storage _sd, bytes calldata _authToken) internal view {
        if (_sd.isAllowlisted) {
            if (_authToken.length == 0) revert MissingAuthToken(_authToken);
            if (!_authToken.verifyAuthTokenForAddress(address(this), msg.sender, _sd.allowlistSigner)) {
                revert InvalidAllowlistAuthToken();
            }
        }
    }

    function _registerAsOperator(
        AvsGovernanceStorageData storage _sd,
        address _operator,
        uint256[4] calldata _blsKey,
        BLSAuthLibrary.Signature calldata _blsRegistrationSignature,
        address _rewardsReceiver
    ) internal {
        if (_rewardsReceiver == address(0)) revert InvalidRewardsReceiver();
        _setRewardsReceiver(_sd, _rewardsReceiver);
        uint256 _numOfOperatorsLimit = _sd.numOfOperatorsLimit;
        if (_sd.numOfActiveOperators >= _numOfOperatorsLimit) revert NumOfOperatorsLimitReached(_numOfOperatorsLimit);
        if (
            !IBLSAuthSingleton(_sd.blsAuthSingleton).isValidSignature(
                _blsRegistrationSignature, _operator, address(this), _blsKey
            )
        ) revert InvalidBlsRegistrationSignature();

        IAvsGovernanceLogic _avsGovernanceLogic = _sd.avsGovernanceLogic;
        {
            bool _isAvsGovernanceLogicSet = address(_avsGovernanceLogic) != address(0);
            (
                IAvsGovernance.StakingContractDetails[] memory _minStakePerStakingContract,
                IAvsGovernance.VotingPowerMultiplier[] memory _votingPowerMultipliers
            ) = _calculateStakingContractDetailsAndMultipliers(_sd, _sd.stakingContracts);
            uint256 _votingPower = _getVotingPower(_sd, _operator, _votingPowerMultipliers);

            {
                bool _isActive = (_votingPower >= _sd.minVotingPower)
                    && OTHENTIC_REGISTRY.isValidStakeAmount(_operator, _minStakePerStakingContract, address(this));
                if (!_isActive) revert NotEnoughVotingPower();
                if (_isAvsGovernanceLogicSet) {
                    _avsGovernanceLogic.beforeOperatorRegistered(_operator, _votingPower, _blsKey, _rewardsReceiver);
                }
                _triggerL2OperatorRegistration(_sd, _operator, _votingPower, _blsKey, _rewardsReceiver);
                ++_sd.numOfActiveOperators;
                _sd.isOperatorRegistered[_operator] = 1;
            }

            if (_isAvsGovernanceLogicSet) {
                _avsGovernanceLogic.afterOperatorRegistered(_operator, _votingPower, _blsKey, _rewardsReceiver);
            }
        }

        emit OperatorRegistered(_operator, _blsKey);
    }

    function _registerOperatorToEigenLayer(
        AvsGovernanceStorageData storage _sd,
        address _operator,
        ISignatureUtils.SignatureWithSaltAndExpiry memory _eigenSig
    ) internal {
        _sd.avsDirectoryContract.registerOperatorToAVS(_operator, _eigenSig);
        emit OperatorRegisteredToEigenLayer(_operator);
    }

    function _registerOperatorToSymbiotic(address _operator, SymbioticOptInSignature memory _symbioticSig) internal {
        IOptInService _optInService = OTHENTIC_REGISTRY.optInService();
        _optInService.optIn(_operator, address(this), _symbioticSig.deadline, _symbioticSig.data);
        emit OperatorRegisteredToSymbiotic(_operator);
    }

    function _unregisterAsOperator(AvsGovernanceStorageData storage _sd, address _operator) internal {
        _triggerL2Unregister(_sd, _operator);
        --_sd.numOfActiveOperators;
        _sd.isOperatorRegistered[_operator] = 0;

        emit OperatorUnregistered(_operator);
    }

    function _triggerL2OperatorRegistration(
        AvsGovernanceStorageData storage _sd,
        address _operator,
        uint256 _votingPower,
        uint256[4] calldata _blsKey,
        address _rewardsReceiver
    ) internal {
        bytes memory _registerOperatorMessage =
            MessagesLibrary.BuildRegisterOperatorMessage(_operator, _votingPower, _blsKey, _rewardsReceiver);
        _sd.messageHandler.sendMessage(abi.encode(_registerOperatorMessage, uint32(0)));
    }

    function _triggerL2Unregister(AvsGovernanceStorageData storage _sd, address _operator) internal {
        bytes memory _unRegisterMessage = MessagesLibrary.BuildUnregisterRequestMessage(_operator);
        _sd.messageHandler.sendMessage(abi.encode(_unRegisterMessage, uint32(0)));
    }

    function _triggerL2BatchClearance(
        AvsGovernanceStorageData storage _sd,
        bytes memory _operators,
        uint256 _lastPayedTask,
        uint32 _remoteEid
    ) internal {
        bytes memory _clearMessage = MessagesLibrary.BuildBatchClearRequestMessage(_operators, _lastPayedTask);
        _sd.messageHandler.sendMessage(abi.encode(_clearMessage, _remoteEid));
    }

    // Staking Contracts must be sorted in ascending order for EigenLayer's rewards coordinator
    function _setSupportedStakingContracts(
        AvsGovernanceStorageData storage _sd,
        IAvsGovernance.StakingContractInfo[] memory _stakingContractsDetails
    ) internal {
        delete _sd.stakingContracts;
        uint160 _lastSeen = 0;
        for (uint256 i = 0; i < _stakingContractsDetails.length;) {
            IAvsGovernance.StakingContractInfo memory _stakingContractDetails = _stakingContractsDetails[i];
            if (uint160(_stakingContractDetails.stakingContract) < _lastSeen) {
                revert StakingContractsNotInAscendingOrder();
            }
            _lastSeen = uint160(_stakingContractDetails.stakingContract);
            if (_stakingContractDetails.stakingContract == address(0)) revert InvalidStakingContract();
            _sd.stakingContracts.push(_stakingContractDetails.stakingContract);
            _sd.stakingContractToSharedSecurityProvider[_stakingContractDetails.stakingContract] =
                _stakingContractDetails.sharedSecurityProvider;
            if (
                _stakingContractDetails.sharedSecurityProvider == SharedSecurityProvider.Symbiotic
                    && IBaseDelegator(IVaultStorage(_stakingContractsDetails[i].stakingContract).delegator())
                        .maxNetworkLimit(bytes32(uint256(uint160(address(this))) << 96 | 0)) == 0
            ) {
                IBaseDelegator(IVaultStorage(_stakingContractsDetails[i].stakingContract).delegator())
                    .setMaxNetworkLimit(0, type(uint256).max);
            }
            unchecked {
                ++i;
            }
        }
        emit setNewSupportedStakingContracts(_sd.stakingContracts);
    }

    function _buildRewardsSubmission(
        IRewardsCoordinator.OperatorReward[] memory _operators,
        uint32 _startTimestamp,
        uint32 _duration,
        address _token
    ) internal view returns (IRewardsCoordinator.OperatorDirectedRewardsSubmission[] memory) {
        AvsGovernanceStorageData storage _sd = _getStorage();
        IRewardsCoordinator.OperatorDirectedRewardsSubmission[] memory _submissions =
            new IRewardsCoordinator.OperatorDirectedRewardsSubmission[](1);
        _submissions[0] = IRewardsCoordinator.OperatorDirectedRewardsSubmission({
            strategiesAndMultipliers: _buildStrategyAndMultipliers(_sd),
            token: IERC20(_token),
            operatorRewards: _operators,
            startTimestamp: _startTimestamp,
            duration: _duration,
            description: ""
        });

        return _submissions;
    }

    /// @dev https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/proxy/Proxy.sol#L22-L45
    function _delegate(address _implementation) internal {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), _implementation, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    // PRIVATE FUNCTIONS

    function _getVotingPower(
        AvsGovernanceStorageData storage _sd,
        address _operator,
        IAvsGovernance.VotingPowerMultiplier[] memory _votingPowerMultipliers
    ) private view returns (uint256) {
        uint256 _maxEffBalance = _sd.maxEffectiveBalance;
        uint256 _votingPower = OTHENTIC_REGISTRY.getVotingPower(_operator, _votingPowerMultipliers, address(this));
        if (_votingPower > _maxEffBalance && _maxEffBalance > 0) {
            _votingPower = _maxEffBalance;
        }
        return _votingPower;
    }

    function _getDefaultStrategies() private view returns (IAvsGovernance.StakingContractInfo[] memory) {
        return OTHENTIC_REGISTRY.getDefaultStrategies(block.chainid);
    }

    function _getEigenStrategies() private view returns (address[] memory _strategies) {
        return _getSharedSecurityStakingContracts(IAvsGovernance.SharedSecurityProvider.EigenLayer);
    }

    function _getSharedSecurityStakingContracts(IAvsGovernance.SharedSecurityProvider _sharedSecurityProvider)
        private
        view
        returns (address[] memory _stakingContracts)
    {
        AvsGovernanceStorageData storage _sd = _getStorage();
        address[] storage _existingStakingContracts = _sd.stakingContracts;
        uint256 _length = _existingStakingContracts.length;
        _stakingContracts = new address[](_length);
        uint256 _count = 0;
        for (uint256 i = 0; i < _length;) {
            address _stakingContract = _existingStakingContracts[i];
            if (_sd.stakingContractToSharedSecurityProvider[_stakingContract] == _sharedSecurityProvider) {
                _stakingContracts[_count] = _stakingContract;
                _count++;
            }
            unchecked {
                ++i;
            }
        }
        assembly {
            mstore(_stakingContracts, _count)
        }
    }

    function _withdrawRewards(
        address _operator,
        address _rewardsReceiver,
        uint256 _lastPayedTask,
        uint256 _feeToClaim,
        IL1AvsTreasury _avsTreasury
    ) private returns (bool _success) {
        if (_rewardsReceiver != address(0)) {
            _success = _avsTreasury.withdrawRewards(_rewardsReceiver, _lastPayedTask, _feeToClaim);
        } else {
            ///TODO: This is temporary and all existing operator must set a rewards receiver address.
            _success = _avsTreasury.withdrawRewards(_operator, _lastPayedTask, _feeToClaim);
        }
    }

    function _setStakingContractMultiplier(
        AvsGovernanceStorageData storage _sd,
        VotingPowerMultiplier calldata _votingPowerMultiplier
    ) private {
        if (_votingPowerMultiplier.multiplier > type(uint96).max) revert InvalidMultiplier();
        _sd.multipliers[_votingPowerMultiplier.stakingContract] = _votingPowerMultiplier.multiplier;
        emit SetStakingContractMultiplier(_votingPowerMultiplier.stakingContract, _votingPowerMultiplier.multiplier);
    }

    function _setRewardsReceiver(AvsGovernanceStorageData storage _sd, address _rewardsReceiver) private {
        _sd.rewardsReceiver[msg.sender] = _rewardsReceiver;
        emit SetRewardsReceiver(msg.sender, _rewardsReceiver);
    }

    function _setAvsName(AvsGovernanceStorageData storage _sd, string calldata _avsName) private {
        if (bytes(_avsName).length == 0) revert EmptyAvsName();
        _sd.avsName = _avsName;
        emit SetAvsName(_avsName);
    }
}
