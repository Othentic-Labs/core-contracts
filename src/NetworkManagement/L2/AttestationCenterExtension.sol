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

import "openzeppelin-contracts-upgradeable/contracts/access/AccessControlUpgradeable.sol";

import "@othentic/NetworkManagement/Common/interfaces/IOBLS.sol";
import "@othentic/NetworkManagement/Common/interfaces/IMessageHandler.sol";
import "@othentic/NetworkManagement/Common/OthenticAccessControl.sol";

import "@othentic/NetworkManagement/L2/interfaces/IAvsLogic.sol";
import "@othentic/NetworkManagement/L2/interfaces/IBeforePaymentsLogic.sol";
import "@othentic/NetworkManagement/L2/interfaces/IFeeCalculator.sol";
import "@othentic/NetworkManagement/L2/interfaces/IInternalTaskHandler.sol";
import {IAttestationCenter} from "@othentic/NetworkManagement/L2/interfaces/IAttestationCenter.sol";
import {IObsoleteAttestationCenter} from "@othentic/NetworkManagement/L2/interfaces/IObsoleteAttestationCenter.sol";
import {IAttestationCenterExtension} from "@othentic/NetworkManagement/L2/interfaces/IAttestationCenterExtension.sol";
import "@othentic/NetworkManagement/L2/AttestationCenterStorage.sol";
import "@othentic/NetworkManagement/L2/TaskDefinitionLibrary.sol";
import "@othentic/NetworkManagement/L2/AttestationCenterPausable.sol";

import {ReentrancyGuardUpgradeable} from
    "openzeppelin-contracts-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";
import {MessagesLibrary} from "@othentic/NetworkManagement/Common/MessagesLibrary.sol";
import {RolesLibrary} from "@othentic/NetworkManagement/Common/RolesLibrary.sol";
import {PauserRolesLibrary} from "@othentic/NetworkManagement/Common/PauserRolesLibrary.sol";
import {BLSAuthLibrary} from "@othentic/NetworkManagement/Common/BLSAuthLibrary.sol";
import {ObsoleteAttestationCenter} from "./ObsoleteAttestationCenter.sol";

/**
 * @author Othentic Labs LTD.
 * @notice Terms of Service: https://www.othentic.xyz/terms-of-service
 */
contract AttestationCenterExtension is
    AttestationCenterPausable,
    ReentrancyGuardUpgradeable,
    IAttestationCenterExtension
{
    using TaskDefinitionLibrary for TaskDefinitions;

    address public immutable OBSOLETE_IMPLEMENTATION;

    fallback() external {
        _delegate(OBSOLETE_IMPLEMENTATION);
    }

    constructor(address _obsoleteImplementation) {
        if (_obsoleteImplementation == address(0)) {
            revert ZeroAddress();
        }
        OBSOLETE_IMPLEMENTATION = _obsoleteImplementation;
    }

    // ------------------ Avs Governance Interface ------------------
    function setAvsLogic(IAvsLogic _avsLogic)
        external
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
        whenFlowNotPaused(PauserRolesLibrary.SET_AVS_LOGIC_FLOW)
    {
        _getStorage().avsLogic = _avsLogic;
        emit SetAvsLogic(address(_avsLogic));
    }

    function setBeforePaymentsLogic(IBeforePaymentsLogic _beforePaymentsLogic)
        external
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
        whenFlowNotPaused(PauserRolesLibrary.SET_AVS_LOGIC_FLOW)
    {
        _getStorage().beforePaymentsLogic = _beforePaymentsLogic;
        emit SetBeforePaymentsLogic(address(_beforePaymentsLogic));
    }

    function setFeeCalculator(IFeeCalculator _feeCalculator)
        external
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
        whenFlowNotPaused(PauserRolesLibrary.SET_AVS_LOGIC_FLOW)
    {
        _getStorage().feeCalculator = _feeCalculator;
        emit SetFeeCalculator(address(_feeCalculator));
    }

    function setInternalTaskHandler(IInternalTaskHandler _internalTaskHandler)
        external
        onlyRole(RolesLibrary.OPERATIONS_MULTISIG)
    {
        _getStorage().internalTaskHandler = _internalTaskHandler;
        emit SetInternalTaskHandler(address(_internalTaskHandler));
    }

    function transferAvsGovernanceMultisig(address _newAvsGovernanceMultisig)
        external
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
    {
        _revokeRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG, msg.sender);
        _grantRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG, _newAvsGovernanceMultisig);
        emit SetAvsGovernanceMultisig(_newAvsGovernanceMultisig);
    }

    function setTaskDefinitionMinVotingPower(uint16 _taskDefinitionId, uint256 _minimumVotingPower)
        external
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
        whenFlowNotPaused(PauserRolesLibrary.CREATE_NEW_TASK_DEFINITION_FLOW)
    {
        AttestationCenterStorageData storage _sd = _getStorage();
        TaskDefinition storage _taskDefinition = _getTaskDefinition(_sd, _taskDefinitionId);
        _taskDefinition.minimumVotingPower = _minimumVotingPower;
        _sd.obls.setTotalVotingPowerPerTaskDefinition(_taskDefinitionId, _sd.numOfTotalOperators, _minimumVotingPower);
        emit SetMinimumTaskDefinitionVotingPower(_minimumVotingPower);
    }

    function setTaskDefinitionRestrictedAttesters(uint16 _taskDefinitionId, uint256[] calldata _restrictedAttesterIds)
        public
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
        whenFlowNotPaused(PauserRolesLibrary.CREATE_NEW_TASK_DEFINITION_FLOW)
    {
        if (!_isSorted(_restrictedAttesterIds)) revert InvalidRestrictedAttesterIds();
        AttestationCenterStorageData storage _sd = _getStorage();
        TaskDefinition storage _taskDefinition = _getTaskDefinition(_sd, _taskDefinitionId);
        _taskDefinition.restrictedAttesterIds = _restrictedAttesterIds;
        _sd.obls.setTotalVotingPowerPerRestrictedTaskDefinition(
            _taskDefinitionId, _taskDefinition.minimumVotingPower, _restrictedAttesterIds
        );
        emit SetRestrictedAttester(_taskDefinitionId, _restrictedAttesterIds);
    }

    function setTaskDefinitionMaximumNumberOfAttesters(uint16 _taskDefinitionId, uint256 _maximumNumberOfAttesters)
        public
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
        whenFlowNotPaused(PauserRolesLibrary.CREATE_NEW_TASK_DEFINITION_FLOW)
    {
        AttestationCenterStorageData storage _sd = _getStorage();
        TaskDefinition storage _taskDefinition = _getTaskDefinition(_sd, _taskDefinitionId);
        uint256 _restrictedLength = _taskDefinition.restrictedAttesterIds.length;
        if (_restrictedLength > 0 && _maximumNumberOfAttesters > _restrictedLength) {
            revert InvalidMaximumNumberOfAttesters();
        }
        _taskDefinition.maximumNumberOfAttesters = _maximumNumberOfAttesters;
        emit SetMaximumNumberOfAttesters(_taskDefinitionId, _maximumNumberOfAttesters);
    }

    function setIsOpenAggregator(bool _isOpenAggregator) external onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG) {
        AttestationCenterStorageData storage _sd = _getStorage();
        _sd.isOpenAggregator = _isOpenAggregator;
        emit IsOpenAggregatorSet(_isOpenAggregator);
    }

    function setEjector(address _ejector) external onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG) {
        _grantRole(RolesLibrary.EJECTOR, _ejector);
    }

    function revokeEjector(address _ejector) external onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG) {
        _revokeRole(RolesLibrary.EJECTOR, _ejector);
    }

    function createNewTaskDefinition(string memory _name, TaskDefinitionParamsV2 calldata _taskDefinitionParams)
        external
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
        whenFlowNotPaused(PauserRolesLibrary.CREATE_NEW_TASK_DEFINITION_FLOW)
        returns (uint16 _id)
    {
        return _createNewTaskDefinition(_name, _taskDefinitionParams);
    }

    function setOblsSharesSyncer(address _oblsSharesSyncer) external onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG) {
        _getStorage().obls.setOblsSharesSyncer(_oblsSharesSyncer);
    }

    // ------------------ Operations Interface ------------------
    function transferMessageHandler(address _newMessageHandler) external onlyRole(RolesLibrary.OPERATIONS_MULTISIG) {
        AttestationCenterStorageData storage _sd = _getStorage();
        _revokeRole(RolesLibrary.MESSAGE_HANDLER, address(_sd.messageHandler));
        _grantRole(RolesLibrary.MESSAGE_HANDLER, _newMessageHandler);
        _sd.messageHandler = IMessageHandler(_newMessageHandler);
        emit SetMessageHandler(_newMessageHandler);
    }

    // PRIVATE FUNCTIONS

    function _createNewTaskDefinition(string memory _name, TaskDefinitionParamsV2 memory _taskDefinitionParams)
        private
        returns (uint16 _id)
    {
        AttestationCenterStorageData storage _sd = _getStorage();
        uint256 _numOfTotalOperators = _sd.numOfTotalOperators;
        bool _isRestricted = _taskDefinitionParams.restrictedAttesterIds.length > 0;
        _id = _sd.taskDefinitions.createNewTaskDefinition(_name, _taskDefinitionParams);
        if (_isRestricted) {
            if (!_isSorted(_taskDefinitionParams.restrictedAttesterIds)) revert InvalidRestrictedAttesterIds();
            if (_taskDefinitionParams.maximumNumberOfAttesters > _taskDefinitionParams.restrictedAttesterIds.length) {
                revert InvalidMaximumNumberOfAttesters();
            }
            _sd.obls.setTotalVotingPowerPerRestrictedTaskDefinition(
                _id, _taskDefinitionParams.minimumVotingPower, _taskDefinitionParams.restrictedAttesterIds
            );
        } else if (_taskDefinitionParams.minimumVotingPower > 0) {
            _sd.obls.setTotalVotingPowerPerTaskDefinition(
                _id, _numOfTotalOperators, _taskDefinitionParams.minimumVotingPower
            );
        }
    }

    function _getTaskDefinition(AttestationCenterStorageData storage _sd, uint16 _taskDefinitionId)
        private
        view
        returns (TaskDefinition storage)
    {
        TaskDefinition storage _taskDefinition = _sd.taskDefinitions.getTaskDefinition(_taskDefinitionId);
        if (_taskDefinition.taskDefinitionId != _taskDefinitionId) revert TaskDefinitionNotFound(_taskDefinitionId);
        return _taskDefinition;
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

    function _isSorted(uint256[] memory _arr) private pure returns (bool) {
        uint256 _len = _arr.length;
        if (_len <= 1) return true;
        unchecked {
            for (uint256 i = 0; i < _len - 1; i++) {
                if (_arr[i] >= _arr[i + 1]) return false;
            }
        }
        return true;
    }

    function _getStorage() internal pure returns (AttestationCenterStorageData storage _sd) {
        return AttestationCenterStorage.load();
    }
}
