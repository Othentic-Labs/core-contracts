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

import {IObsoleteAttestationCenter} from "./interfaces/IObsoleteAttestationCenter.sol";
import {
    TaskDefinitionLibrary,
    TaskDefinitionParams,
    TaskDefinitionParamsV2,
    TaskDefinition,
    TaskDefinitions
} from "./TaskDefinitionLibrary.sol";
import {AccessControlUpgradeable} from
    "openzeppelin-contracts-upgradeable/contracts/access/AccessControlUpgradeable.sol";
import {RolesLibrary} from "@othentic/NetworkManagement/Common/RolesLibrary.sol";
import {PauserRolesLibrary} from "@othentic/NetworkManagement/Common/PauserRolesLibrary.sol";
import {AttestationCenterPausable} from "@othentic/NetworkManagement/L2/AttestationCenterPausable.sol";
import {
    AttestationCenterStorage,
    AttestationCenterStorageData
} from "@othentic/NetworkManagement/L2/AttestationCenterStorage.sol";

contract ObsoleteAttestationCenter is
    IObsoleteAttestationCenter,
    AccessControlUpgradeable,
    AttestationCenterPausable
{
    using TaskDefinitionLibrary for TaskDefinitions;

    // @backward-compatibility used in mainnet and older CLI versions
    function createNewTaskDefinition(string memory _name, TaskDefinitionParams calldata _taskDefinitionParams)
        external
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
        whenFlowNotPaused(PauserRolesLibrary.CREATE_NEW_TASK_DEFINITION_FLOW)
        returns (uint16 _id)
    {
        TaskDefinitionParamsV2 memory _TaskDefinitionParamsV2 = TaskDefinitionParamsV2(
            _taskDefinitionParams.blockExpiry,
            _taskDefinitionParams.baseRewardFeeForAttesters,
            _taskDefinitionParams.baseRewardFeeForPerformer,
            _taskDefinitionParams.baseRewardFeeForAggregator,
            _taskDefinitionParams.disputePeriodBlocks,
            _taskDefinitionParams.minimumVotingPower,
            _taskDefinitionParams.restrictedAttesterIds,
            0
        );
        return _createNewTaskDefinition(_name, _TaskDefinitionParamsV2);
    }

    // @backward-compatibility used in mainnet and older CLI versions
    function getTaskDefinitionMaximumNumberOfOperators(uint16 _taskDefinitionId) external view returns (uint256) {
        return _getStorage().taskDefinitions.getMaximumNumberOfAttesters(_taskDefinitionId);
    }

    // @backward-compatibility used in mainnet and older CLI versions
    function getTaskDefinitionRestrictedOperators(uint16 _taskDefinitionId) external view returns (uint256[] memory) {
        return _getStorage().taskDefinitions.getRestrictedAttesterIds(_taskDefinitionId);
    }

    // @backward-compatibility used in mainnet and older CLI versions
    function setTaskDefinitionRestrictedOperators(uint16 _taskDefinitionId, uint256[] calldata _restrictedAttesterIds)
        external
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
        whenFlowNotPaused(PauserRolesLibrary.CREATE_NEW_TASK_DEFINITION_FLOW)
    {
        if (!_isSorted(_restrictedAttesterIds)) {
            revert InvalidRestrictedAttesterIds();
        }
        AttestationCenterStorageData storage _sd = _getStorage();
        TaskDefinition storage _taskDefinition = _getTaskDefinition(_sd, _taskDefinitionId);
        _taskDefinition.restrictedAttesterIds = _restrictedAttesterIds;
        _sd.obls.setTotalVotingPowerPerRestrictedTaskDefinition(
            _taskDefinitionId, _taskDefinition.minimumVotingPower, _restrictedAttesterIds
        );
        emit SetRestrictedAttester(_taskDefinitionId, _restrictedAttesterIds);
    }

    // @backward-compatibility used in mainnet and older CLI versions
    function setTaskDefinitionMaximumNumberOfOperators(uint16 _taskDefinitionId, uint256 _maximumNumberOfAttesters)
        external
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

    // @obsolete - Use avsTreasury()
    function vault() external view returns (address) {
        return address(_getStorage().avsTreasury);
    }

    function migrateAddTotalVotingPowerSyncTaskDefinition() external onlyRole(RolesLibrary.OPERATIONS_MULTISIG) {
        uint16 TOTAL_VOTING_POWER_CALC_TASK_DEFINITION_ID =
            TaskDefinitionLibrary.TOTAL_VOTING_POWER_CALC_TASK_DEFINITION_ID;
        TaskDefinition storage _defaultTaskDefinition =
            _getStorage().taskDefinitions.getTaskDefinition(TOTAL_VOTING_POWER_CALC_TASK_DEFINITION_ID);
        if (
            _defaultTaskDefinition.taskDefinitionId == TOTAL_VOTING_POWER_CALC_TASK_DEFINITION_ID
                && keccak256(abi.encodePacked(_defaultTaskDefinition.name))
                    == keccak256(abi.encodePacked("Voting Power Sync Task"))
                && _defaultTaskDefinition.blockExpiry == type(uint256).max
        ) {
            revert AlreadyMigrated();
        }
        _defaultTaskDefinition.name = "Total Voting Power Sync Task Definition";
        _defaultTaskDefinition.taskDefinitionId = TaskDefinitionLibrary.TOTAL_VOTING_POWER_CALC_TASK_DEFINITION_ID;
        _defaultTaskDefinition.blockExpiry = type(uint256).max;
    }

    // Internal helper functions
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

    function _createNewTaskDefinition(string memory _name, TaskDefinitionParamsV2 memory _taskDefinitionParams)
        private
        returns (uint16 _id)
    {
        AttestationCenterStorageData storage _sd = _getStorage();
        uint256 _numOfTotalOperators = _sd.numOfTotalOperators;
        bool _isRestricted = _taskDefinitionParams.restrictedAttesterIds.length > 0;
        _id = _sd.taskDefinitions.createNewTaskDefinition(_name, _taskDefinitionParams);
        if (_isRestricted) {
            if (!_isSorted(_taskDefinitionParams.restrictedAttesterIds)) {
                revert InvalidRestrictedAttesterIds();
            }
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
        if (_taskDefinition.taskDefinitionId != _taskDefinitionId) {
            revert TaskDefinitionNotFound(_taskDefinitionId);
        }
        return _taskDefinition;
    }

    function _getStorage() internal pure returns (AttestationCenterStorageData storage _sd) {
        return AttestationCenterStorage.load();
    }
}
