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
import {IAvsGovernanceExtension} from "@othentic/NetworkManagement/L1/interfaces/IAvsGovernanceExtension.sol";
import {IAvsGovernanceLogic} from "@othentic/NetworkManagement/L1/interfaces/IAvsGovernanceLogic.sol";
import {IOthenticRegistry} from "@othentic/NetworkManagement/L1/interfaces/IOthenticRegistry.sol";
import {ISignatureUtils} from "@eigenlayer/contracts/interfaces/ISignatureUtils.sol";
import {IMessageHandler} from "@othentic/NetworkManagement/Common/interfaces/IMessageHandler.sol";
import {IBLSAuthSingleton} from "@othentic/NetworkManagement/Common/interfaces/IBLSAuthSingleton.sol";
import {IAvsTreasury} from "@othentic/NetworkManagement/Common/interfaces/IAvsTreasury.sol";
import {RolesLibrary} from "@othentic/NetworkManagement/Common/RolesLibrary.sol";
import {PauserRolesLibrary} from "@othentic/NetworkManagement/Common/PauserRolesLibrary.sol";
import {SignedAuthTokenLibrary} from "@othentic/NetworkManagement/Common/SignedAuthTokenLibrary.sol";
import {BLSAuthLibrary} from "@othentic/NetworkManagement/Common/BLSAuthLibrary.sol";
import {MessagesLibrary} from "@othentic/NetworkManagement/Common/MessagesLibrary.sol";
import {ReentrancyGuardUpgradeable} from
    "openzeppelin-contracts-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";

contract AvsGovernanceExtension is AvsGovernancePausable, ReentrancyGuardUpgradeable, IAvsGovernanceExtension {
    using SignedAuthTokenLibrary for bytes;
    using SafeERC20 for IERC20;

    address public immutable OBSOLETE_IMPLEMENTATION;

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

    fallback() external {
        _delegate(OBSOLETE_IMPLEMENTATION);
    }

    constructor(address _obsoleteImplementation) {
        if (_obsoleteImplementation == address(0)) {
            revert ZeroAddress();
        }
        OBSOLETE_IMPLEMENTATION = _obsoleteImplementation;
    }

    // -------------------- Layer 2 Interface -------------------- //
    /// @dev Can only be called by AttestationCenter::requestPayment using MessageHandler, pauseFlow protection is enforced on AttestationCenter.
    function withdrawBatchRewards(PaymentRequestMessage[] memory _operators, uint256 _lastPayedTask, uint32 _remoteEid)
        external
        onlyRole(RolesLibrary.MESSAGE_HANDLER)
    {
        AvsGovernanceStorageData storage _sd = _getStorage();
        IAvsTreasury _avsTreasury = _sd.avsTreasury;
        PaymentRequestMessage memory _paymentRequestMessage;
        for (uint256 i = 0; i < _operators.length; i++) {
            _paymentRequestMessage = _operators[i];
            address _operator = _paymentRequestMessage.operator;
            if (_operator == address(0)) break;
            address _rewardsReceiver = _sd.rewardsReceiver[_operator];
            bool _success = _withdrawRewards(
                _operator, _rewardsReceiver, _lastPayedTask, _paymentRequestMessage.feeToClaim, _avsTreasury
            );
            if (!_success) _operators[i].feeToClaim = 0;
        }
        _triggerL2BatchClearance(_sd, abi.encode(_operators), _lastPayedTask, _remoteEid);
    }

    // -------------------- AvsGovernance Multisig Interface -------------------- //
    function setNumOfOperatorsLimit(uint256 _newLimitOfNumOfOperators)
        external
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
    {
        AvsGovernanceStorageData storage _sd = _getStorage();
        uint256 _numOfActiveOperators = _sd.numOfActiveOperators;
        if (_numOfActiveOperators > _newLimitOfNumOfOperators) {
            revert NumOfActiveOperatorsIsGreaterThanNumOfOperatorLimit(_numOfActiveOperators, _newLimitOfNumOfOperators);
        }
        _sd.numOfOperatorsLimit = _newLimitOfNumOfOperators;
        emit SetNumOfOperatorsLimit(_newLimitOfNumOfOperators);
    }

    function setIsAllowlisted(bool _isAllowlisted) external onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG) {
        _getStorage().isAllowlisted = _isAllowlisted;
        emit SetIsAllowlisted(_isAllowlisted);
    }

    function setAvsGovernanceLogic(IAvsGovernanceLogic _avsGovernanceLogic)
        external
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
        whenFlowNotPaused(PauserRolesLibrary.SET_AVS_LOGIC_FLOW)
    {
        _getStorage().avsGovernanceLogic = _avsGovernanceLogic;
        emit SetAvsGovernanceLogic(address(_avsGovernanceLogic));
    }

    function setAvsGovernanceMultiplierSyncer(address _newAvsGovernanceMultiplierSyncer)
        external
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
    {
        AvsGovernanceStorageData storage _sd = _getStorage();
        _revokeRole(RolesLibrary.MULTIPLIER_SYNCER, _sd.avsGovernanceMultiplierSyncer);
        _grantRole(RolesLibrary.MULTIPLIER_SYNCER, _newAvsGovernanceMultiplierSyncer);
        emit SetAvsGovernanceMultiplierSyncer(_newAvsGovernanceMultiplierSyncer);
        _sd.avsGovernanceMultiplierSyncer = _newAvsGovernanceMultiplierSyncer;
    }

    function transferAvsGovernanceMultisig(address _newAvsGovernanceMultisig)
        external
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
    {
        _revokeRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG, msg.sender);
        _grantRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG, _newAvsGovernanceMultisig);
        emit SetAvsGovernanceMultisig(_newAvsGovernanceMultisig);
    }

    function rescueFunds() external onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG) {
        AvsGovernanceStorageData storage _sd = _getStorage();
        IERC20 _token = IERC20(_sd.avsTreasury.getToken());

        uint256 _balance = _token.balanceOf(address(this));
        if (_balance > 0) {
            _token.safeTransfer(msg.sender, _balance);
            emit FundsRescued(address(_token), msg.sender, _balance);
        }
    }

    // -------------------- Avs Governance Multiplier Syncer Interface -------------------- ///

    function setRewardsReceiverModificationDelay(uint256 _rewardsReceiverModificationDelay)
        external
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
    {
        _getStorage().rewardsReceiverModificationDelay = _rewardsReceiverModificationDelay;
        emit SetRewardsReceiverModificationDelay(_rewardsReceiverModificationDelay);
    }

    function setMaxEffectiveBalance(uint256 _maxBalance) external onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG) {
        _getStorage().maxEffectiveBalance = _maxBalance;
        emit MaxEffectiveBalanceSet(_maxBalance);
    }

    function setMinStakesForStakingContract(address _stakingContract, uint256 _minShares)
        external
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

    function setMinVotingPower(uint256 _minVotingPower) external onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG) {
        _getStorage().minVotingPower = _minVotingPower;
        emit MinVotingPowerSet(_minVotingPower);
    }

    // -------------------- Operations Multisig Interface -------------------- //

    function setBLSAuthSingleton(address _blsAuthSingleton) external onlyRole(RolesLibrary.OPERATIONS_MULTISIG) {
        _getStorage().blsAuthSingleton = _blsAuthSingleton;
        emit BLSAuthSingletonSet(_blsAuthSingleton);
    }

    function transferMessageHandler(address _newMessageHandler) external onlyRole(RolesLibrary.OPERATIONS_MULTISIG) {
        AvsGovernanceStorageData storage _sd = _getStorage();
        _revokeRole(RolesLibrary.MESSAGE_HANDLER, address(_sd.messageHandler));
        _grantRole(RolesLibrary.MESSAGE_HANDLER, _newMessageHandler);
        _sd.messageHandler = IMessageHandler(_newMessageHandler);
        emit SetMessageHandler(_newMessageHandler);
    }

    function setAllowlistSigner(address _allowlistSigner) external onlyRole(RolesLibrary.OPERATIONS_MULTISIG) {
        _getStorage().allowlistSigner = _allowlistSigner;
        emit SetAllowlistSigner(_allowlistSigner);
    }

    // -------------------- IServiceManager Interface -------------------- //

    function avsDirectory() external view returns (address) {
        return address(_getStorage().avsDirectoryContract);
    }

    // -------------------- AvsGovernance configuration Interface -------------------- //
    function getNumOfOperatorsLimit() external view returns (uint256 numOfOperatorsLimitView) {
        return _getStorage().numOfOperatorsLimit;
    }

    function getL1MessageHandler() external view returns (address) {
        return address(_getStorage().messageHandler);
    }
    // INTERNAL FUNCTIONS

    function _triggerL2BatchClearance(
        AvsGovernanceStorageData storage _sd,
        bytes memory _operators,
        uint256 _lastPayedTask,
        uint32 _remoteEid
    ) internal {
        bytes memory _clearMessage = MessagesLibrary.BuildBatchClearRequestMessage(_operators, _lastPayedTask);
        _sd.messageHandler.sendMessage(abi.encode(_clearMessage, _remoteEid));
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

    function _getStorage() internal pure returns (AvsGovernanceStorageData storage _sd) {
        return AvsGovernanceStorage.load();
    }

    // PRIVATE FUNCTIONS
    function _withdrawRewards(
        address _operator,
        address _rewardsReceiver,
        uint256 _lastPayedTask,
        uint256 _feeToClaim,
        IAvsTreasury _avsTreasury
    ) private returns (bool _success) {
        if (_rewardsReceiver != address(0)) {
            _success = _avsTreasury.withdrawRewards(_rewardsReceiver, _lastPayedTask, _feeToClaim);
        } else {
            ///TODO: This is temporary and all existing operator must set a rewards receiver address.
            _success = _avsTreasury.withdrawRewards(_operator, _lastPayedTask, _feeToClaim);
        }
    }
}
