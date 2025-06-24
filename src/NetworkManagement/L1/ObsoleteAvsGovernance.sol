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

import {AvsGovernanceStorage, AvsGovernanceStorageData} from "@othentic/NetworkManagement/L1/AvsGovernanceStorage.sol";
import {AvsGovernancePausable} from "@othentic/NetworkManagement/L1/AvsGovernancePausable.sol";
import {IAvsGovernance} from "@othentic/NetworkManagement/L1/interfaces/IAvsGovernance.sol";
import {IObsoleteAvsGovernance} from "@othentic/NetworkManagement/L1/interfaces/IObsoleteAvsGovernance.sol";
import {IOthenticRegistry} from "@othentic/NetworkManagement/L1/interfaces/IOthenticRegistry.sol";
import {IAvsGovernanceLogic} from "@othentic/NetworkManagement/L1/interfaces/IAvsGovernanceLogic.sol";
import {ISignatureUtils} from "@eigenlayer/contracts/interfaces/ISignatureUtils.sol";
import {IBLSAuthSingleton} from "@othentic/NetworkManagement/Common/interfaces/IBLSAuthSingleton.sol";
import {RolesLibrary} from "@othentic/NetworkManagement/Common/RolesLibrary.sol";
import {PauserRolesLibrary} from "@othentic/NetworkManagement/Common/PauserRolesLibrary.sol";
import {SignedAuthTokenLibrary} from "@othentic/NetworkManagement/Common/SignedAuthTokenLibrary.sol";
import {BLSAuthLibrary} from "@othentic/NetworkManagement/Common/BLSAuthLibrary.sol";
import {MessagesLibrary} from "@othentic/NetworkManagement/Common/MessagesLibrary.sol";
import {ReentrancyGuardUpgradeable} from
    "openzeppelin-contracts-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";
import {IVetoSlasher} from "@symbiotic/src/interfaces/slasher/IVetoSlasher.sol";

contract ObsoleteAvsGovernance is IObsoleteAvsGovernance, AvsGovernancePausable, ReentrancyGuardUpgradeable {
    IOthenticRegistry private immutable OTHENTIC_REGISTRY;

    using SignedAuthTokenLibrary for bytes;

    modifier onlyRegisteredOperator() {
        if (_getStorage().isOperatorRegistered[msg.sender] == 0) {
            revert OperatorNotRegistered();
        }
        _;
    }

    modifier onlyUnregisteredOperator() {
        if (_getStorage().isOperatorRegistered[msg.sender] != 0) {
            revert OperatorAlreadyRegistered();
        }
        _;
    }

    constructor(IOthenticRegistry _othenticRegistry) {
        if (address(_othenticRegistry) == address(0)) {
            revert ZeroAddress();
        }
        OTHENTIC_REGISTRY = _othenticRegistry;
    }

    // obsolete - only supports EigenLayer registration
    function registerAsAllowedOperator(
        uint256[4] calldata _blsKey,
        bytes calldata _authToken,
        address _rewardsReceiver,
        ISignatureUtils.SignatureWithSaltAndExpiry calldata _operatorSignature,
        BLSAuthLibrary.Signature calldata _blsRegistrationSignature
    ) external onlyUnregisteredOperator whenFlowNotPaused(PauserRolesLibrary.REGISTRATION_FLOW) nonReentrant {
        AvsGovernanceStorageData storage _sd = _getStorage();
        if (!_sd.isAllowlisted) revert AllowlistDisabled();
        if (!_authToken.verifyAuthTokenForAddress(address(this), msg.sender, _sd.allowlistSigner)) {
            revert InvalidAllowlistAuthToken();
        }
        _registerAsOperator(_sd, msg.sender, _blsKey, _blsRegistrationSignature, _rewardsReceiver);
        _sd.avsDirectoryContract.registerOperatorToAVS(msg.sender, _operatorSignature);
    }

    // obsolete - only supports EigenLayer registration
    function registerAsOperator(
        uint256[4] calldata _blsKey,
        address _rewardsReceiver,
        ISignatureUtils.SignatureWithSaltAndExpiry calldata _operatorSignature,
        BLSAuthLibrary.Signature calldata _blsRegistrationSignature
    ) external onlyUnregisteredOperator whenFlowNotPaused(PauserRolesLibrary.REGISTRATION_FLOW) nonReentrant {
        AvsGovernanceStorageData storage _sd = _getStorage();
        if (_sd.isAllowlisted) revert AllowlistEnabled();
        _registerAsOperator(_sd, msg.sender, _blsKey, _blsRegistrationSignature, _rewardsReceiver);
        _sd.avsDirectoryContract.registerOperatorToAVS(msg.sender, _operatorSignature);
    }

    // @obsolete - auth token required
    function registerOperatorToEigenLayer(ISignatureUtils.SignatureWithSaltAndExpiry memory /*_eigenSig*/ )
        external
        pure
    {
        revert("Obsolete missing the auth token please add or update your CLI");
    }

    // @obsolete - auth token required
    function registerOperatorToSymbiotic(IAvsGovernance.SymbioticOptInSignature memory /*_symbioticSig*/ )
        external
        pure
    {
        revert("Obsolete missing the auth token please add or update your CLI");
    }

    // @obsolete - Use avsTreasury()
    function vault() external view returns (address) {
        return address(_getStorage().avsTreasury);
    }

    // @obsolete - Use minStakeAmountPerStakingContract()
    function minSharesForStrategy(address _stakingContract) external view returns (uint256) {
        return _getStorage().minStakeAmountPerStakingContract[_stakingContract];
    }

    // @obsolete - Use stakingContracts()
    function strategies() external view returns (address[] memory) {
        return _getStorage().stakingContracts;
    }

    // @obsolete - Use multiplier()
    function strategyMultiplier(address _stakingContract) external view returns (uint256) {
        return _getStorage().multipliers[_stakingContract];
    }

    // @obsolete - Use setMinStakesForStakingContract
    function setMinSharesForStrategy(address _stakingContract, uint256 _minShares)
        external
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
    {
        setMinStakesForStakingContract(_stakingContract, _minShares);
    }

    // @obsolete - Use setStakingContractMultiplier
    function setStrategyMultiplier(IAvsGovernance.VotingPowerMultiplier calldata _votingPowerMultiplier)
        external
        onlyRole(RolesLibrary.MULTIPLIER_SYNCER)
    {
        _setStakingContractMultiplier(_getStorage(), _votingPowerMultiplier);
    }

    // @obsolete - Use setStakingContractMultiplierBatch
    function setStrategyMultiplierBatch(IAvsGovernance.VotingPowerMultiplier[] calldata _votingPowerMultipliers)
        external
        onlyRole(RolesLibrary.MULTIPLIER_SYNCER)
    {
        setStakingContractMultiplierBatch(_votingPowerMultipliers);
    }

    // @obsolete - need to use registerAvsToEigenLayer
    function updateAVSMetadataURI(string calldata metadataURI)
        external
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
    {
        _getStorage().avsDirectoryContract.updateAVSMetadataURI(metadataURI);
    }

    // obsolete - only supports EigenLayer, use setSupportedStakingContracts
    function setSupportedStrategies(address[] memory _strategies)
        external
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
        whenFlowNotPaused(PauserRolesLibrary.SET_SUPPORTED_STRATEGIES_FLOW)
    {
        AvsGovernanceStorageData storage _sd = _getStorage();
        IAvsGovernance.StakingContractInfo[] memory _stakingContractsDetails =
            new IAvsGovernance.StakingContractInfo[](_strategies.length);
        for (uint256 i = 0; i < _strategies.length;) {
            _stakingContractsDetails[i] =
                IAvsGovernance.StakingContractInfo(_strategies[i], IAvsGovernance.SharedSecurityProvider.EigenLayer);
            unchecked {
                ++i;
            }
        }
        _setSupportedStakingContracts(_sd, _stakingContractsDetails);
    }

    function setSymbioticResolver(IVetoSlasher _vetoSlasher, address _resolver, bytes calldata _hints) external onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG) {
        _vetoSlasher.setResolver(0, _resolver, _hints);
    }

    // obsolete - only supports EigenLayer deregistration
    function unregisterAsOperator()
        external
        onlyRegisteredOperator
        whenFlowNotPaused(PauserRolesLibrary.REGISTRATION_FLOW)
        nonReentrant
    {
        AvsGovernanceStorageData storage _sd = _getStorage();
        _unregisterAsOperator(msg.sender);
        _sd.avsDirectoryContract.deregisterOperatorFromAVS(msg.sender);
    }

    function setStakingContractMultiplierBatch(IAvsGovernance.VotingPowerMultiplier[] calldata _votingPowerMultipliers)
        public
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

    // @obsolete - Use setMinStakesForStakingContract
    function setMinStakesForStakingContract(address _stakingContract, uint256 _minShares)
        public
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
    {
        AvsGovernanceStorageData storage _sd = AvsGovernanceStorage.load();
        bool _stakingContractFound = false;
        for (uint256 i = 0; i < _sd.stakingContracts.length; i++) {
            if (_sd.stakingContracts[i] == _stakingContract) {
                _stakingContractFound = true;
                break;
            }
        }
        if (!_stakingContractFound) revert InvalidStakingContract();
        _sd.minStakeAmountPerStakingContract[_stakingContract] = _minShares;
        emit MinStakeForStakingContractSet(_stakingContract, _minShares);
    }

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
            if (_stakingContractDetails.stakingContract == address(0)) {
                revert InvalidStakingContract();
            }
            _sd.stakingContracts.push(_stakingContractDetails.stakingContract);
            _sd.stakingContractToSharedSecurityProvider[_stakingContractDetails.stakingContract] =
                _stakingContractDetails.sharedSecurityProvider;
            unchecked {
                ++i;
            }
        }
        emit setNewSupportedStakingContracts(_sd.stakingContracts);
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
        if (_sd.numOfActiveOperators >= _numOfOperatorsLimit) {
            revert NumOfOperatorsLimitReached(_numOfOperatorsLimit);
        }
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

    function _unregisterAsOperator(address _operator) internal {
        AvsGovernanceStorageData storage _sd = _getStorage();
        IAvsGovernanceLogic _avsGovernanceLogic = _sd.avsGovernanceLogic;
        bool _isAvsGovernanceLogicSet = address(_avsGovernanceLogic) != address(0);
        if (_isAvsGovernanceLogicSet) {
            _avsGovernanceLogic.beforeOperatorUnregistered(_operator);
        }

        _triggerL2Unregister(_sd, _operator);
        --_sd.numOfActiveOperators;
        _sd.isOperatorRegistered[_operator] = 0;

        if (_isAvsGovernanceLogicSet) {
            _avsGovernanceLogic.afterOperatorUnregistered(_operator);
        }
        emit OperatorUnregistered(_operator);
    }

    function _triggerL2Unregister(AvsGovernanceStorageData storage _sd, address _operator) internal {
        bytes memory _unRegisterMessage = MessagesLibrary.BuildUnregisterRequestMessage(_operator);
        _sd.messageHandler.sendMessage(abi.encode(_unRegisterMessage, uint32(0)));
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

    function _setRewardsReceiver(AvsGovernanceStorageData storage _sd, address _rewardsReceiver) private {
        _sd.rewardsReceiver[msg.sender] = _rewardsReceiver;
        emit SetRewardsReceiver(msg.sender, _rewardsReceiver);
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

    function _setStakingContractMultiplier(
        AvsGovernanceStorageData storage _sd,
        IAvsGovernance.VotingPowerMultiplier calldata _votingPowerMultiplier
    ) private {
        _sd.multipliers[_votingPowerMultiplier.stakingContract] = _votingPowerMultiplier.multiplier;
        emit SetStakingContractMultiplier(_votingPowerMultiplier.stakingContract, _votingPowerMultiplier.multiplier);
    }

    function _getStorage() internal pure returns (AvsGovernanceStorageData storage _sd) {
        return AvsGovernanceStorage.load();
    }
}
