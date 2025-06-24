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

import {
    IInternalTaskHandler,
    IAttestationCenter,
    InternalTransaction,
    VotingPowerUpdate
} from "./interfaces/IInternalTaskHandler.sol";
import {Initializable} from "openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import {IOBLS} from "@othentic/NetworkManagement/Common/interfaces/IOBLS.sol";
import {TaskDefinitionLibrary} from "@othentic/NetworkManagement/L2/TaskDefinitionLibrary.sol";
import "openzeppelin-contracts-upgradeable/contracts/access/AccessControlUpgradeable.sol";
import {InternalTaskHandlerStorage, InternalTaskHandlerStorageData} from "./InternalTaskHandlerStorage.sol";
import "@othentic/NetworkManagement/Common/RolesLibrary.sol";

/**
 * @author Othentic Labs LTD.
 * @notice Terms of Service: https://www.othentic.xyz/terms-of-service
 */
contract InternalTaskHandler is IInternalTaskHandler, Initializable, AccessControlUpgradeable {
    function initialize(address _attestationCenter, address _obls) external initializer {
        InternalTaskHandlerStorageData storage _sd = _getStorage();
        _sd.obls = IOBLS(_obls);
        _grantRole(RolesLibrary.ATTESTATION_CENTER, _attestationCenter);
    }

    function getLastCommitBlockL1() external view returns (uint256) {
        return _getStorage().lastCommitBlockL1;
    }

    function getLastCommitBlockL2() external view returns (uint256) {
        return _getStorage().lastCommitBlockL2;
    }

    function processTask(IAttestationCenter.TaskInfo calldata _task)
        external
        onlyRole(RolesLibrary.ATTESTATION_CENTER)
    {
        if (_task.taskDefinitionId == TaskDefinitionLibrary.VOTING_POWER_SYNC_TASK_DEFINITION_ID) {
            _votingPowerUpdate(_task);
        } else if (_task.taskDefinitionId == TaskDefinitionLibrary.TOTAL_VOTING_POWER_CALC_TASK_DEFINITION_ID) {
            _triggerInternalTransactionsTask(_task);
        }
        emit TaskProcessed(_task.taskDefinitionId, _task.proofOfTask);
    }

    function _getStorage() internal pure returns (InternalTaskHandlerStorageData storage _sd) {
        return InternalTaskHandlerStorage.load();
    }

    function _votingPowerUpdate(IAttestationCenter.TaskInfo memory _task) internal {
        InternalTaskHandlerStorageData storage _sd = _getStorage();
        IOBLS _obls = _sd.obls;
        VotingPowerUpdate memory _update = abi.decode(_task.data, (VotingPowerUpdate));
        uint256 _lastCommitBlockL1 = _sd.lastCommitBlockL1;
        uint256 _lastCommitBlockL2 = _sd.lastCommitBlockL2;
        if (_lastCommitBlockL1 >= _update.toBlockL1) {
            revert InvalidToBlockL1VsLastCommitBlockL1(_lastCommitBlockL1 + 1);
        }
        if (_lastCommitBlockL2 >= _update.toBlockL2) {
            revert InvalidToBlockL2VsLastCommitBlockL2(_lastCommitBlockL2 + 1);
        }
        if (_update.toBlockL2 >= block.number) {
            revert InvalidToBlockL2VsCurrentHeight(_update.toBlockL2, block.number);
        }
        _sd.lastCommitBlockL1 = _update.toBlockL1;
        _sd.lastCommitBlockL2 = _update.toBlockL2;
        if (_update.toIncrease.length > 0) {
            _obls.increaseBatchOperatorVotingPower(_update.toIncrease);
        }
        if (_update.toDecrease.length > 0) {
            _obls.decreaseBatchOperatorVotingPower(_update.toDecrease);
        }
        emit VotingPowerUpdated(_update.toBlockL1, _update.toBlockL2, _task.proofOfTask);
    }

    function _triggerInternalTransactionsTask(IAttestationCenter.TaskInfo memory _task) private {
        InternalTaskHandlerStorageData storage _sd = _getStorage();
        address _obls = address(_sd.obls);
        InternalTransaction[] memory _transactions = abi.decode(_task.data, (InternalTransaction[]));
        for (uint256 i = 0; i < _transactions.length; i++) {
            InternalTransaction memory _transaction = _transactions[i];
            address _to = _transaction.to;
            bytes memory _data = _transaction.data;
            bytes4 _selector = bytes4(_data);
            bool _isNotAllowedToAddress = _to != _obls;
            bool _isNotAllowedMethodSelector = _selector
                != IOBLS.setTotalVotingPowerPerRestrictedTaskDefinition.selector
                && _selector != IOBLS.setTotalVotingPowerPerTaskDefinition.selector;
            if (_isNotAllowedToAddress || _isNotAllowedMethodSelector) {
                revert InternalTransactionNotAllowed(_to, _data);
            }
            (bool sent, bytes memory err) = _transaction.to.call(_transaction.data);
            if (!sent) {
                revert InternalTransactionRevert(err);
            }
        }
        emit ExecuteInternalTransactionsTask(_transactions);
    }
}
