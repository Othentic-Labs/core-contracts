// SPDX-License-Identifier: MIT
pragma solidity >=0.8.20;
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
import "openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import "@othentic/NetworkManagement/Common/interfaces/IOBLS.sol";
import "@othentic/NetworkManagement/Common/OBLSStorage.sol";
import "@othentic/NetworkManagement/Common/RolesLibrary.sol";
import { BLS } from "@othentic/NetworkManagement/Common/BLS.sol";
import { BN256G2 } from "@othentic/NetworkManagement/Common/BN256G2.sol";
import { BLSAuthLibrary } from "@othentic/NetworkManagement/Common/BLSAuthLibrary.sol";

/**
 * @author Othentic Labs LTD.
 */

contract OBLS is Initializable, AccessControlUpgradeable, IOBLS {
    using BLSAuthLibrary for BLSAuthLibrary.Signature;

    modifier onlyOblsManager {
        if (msg.sender != _getStorage().oblsManager) revert NotOBLSManager();
        _;
    }

    modifier onlyOblsManagerOrSharesSyncer {
        OBLSStorageData storage _sd = _getStorage();
        if (msg.sender != _sd.oblsManager && msg.sender != _sd.oblsSharesSyncer) revert NotOBLSManagerOrShareSyncer();
        _;
    }

    function initialize() public initializer {
        _initialize();
    }

    function _initialize() internal onlyInitializing {
        OBLSStorageData storage _oblsStorageData = _getStorage();
        _oblsStorageData.totalVotingPower = 0;
        _grantRole(RolesLibrary.AVS_FACTORY_ROLE, msg.sender);
    }

    // @obsolete - here just for backwards compatibility - use totalVotingPower
    function totalNumOfSharesOfOperatorsSet() external view returns (uint256) {
        return _getStorage().totalVotingPower;
    }

    // @obsolete - here just for backwards compatibility - use votingPower
    function numOfShares(uint256 _index) external view returns (uint256) {
        return _getStorage().operators[_index].votingPower;
    }

    function totalVotingPower() external view returns (uint256) {
        return _getStorage().totalVotingPower;
    }

    function votingPower(uint256 _index) external view returns (uint256) {
        return _getStorage().operators[_index].votingPower;
    }

    function totalVotingPowerPerTaskDefinition(uint256 _id) external view returns (uint256) {
        return _getStorage().totalVotingPowerPerTaskDefinition[_id];
    }

    function isActive(uint256 _index) external view returns (bool) {
        return _getStorage().operators[_index].isActive;
    }

    // obselete - here just for backwards compatibility - use verifySignature with min voing power
    function verifySignature(
        uint256[2] calldata _message,
        uint256[2] calldata _signature,
        uint256[] calldata _indexes,
        uint256 _requiredVotingPower
    ) external view {        
        (uint256[4] memory _aggPubkey, uint256 _votingPowerSigned) = _calculateAggregatePK(_indexes, 0);
        if (_votingPowerSigned < _requiredVotingPower) revert InsufficientVotingPower();
        (bool _callSuccess, bool _result) = BLS.verifySingle(_signature, _aggPubkey, _message);
        if (!_callSuccess || !_result) revert InvalidOBLSSignature();
    }

    function verifySignature(
        uint256[2] calldata _message,
        uint256[2] calldata _signature,
        uint256[] calldata _indexes,
        uint256 _requiredVotingPower,
        uint256 _minimumVotingPowerPerTaskDefinition
    ) external view {
        if (_requiredVotingPower == 0) revert InvalidRequiredVotingPower();
        (uint256[4] memory _aggPubkey, uint256 _votingPowerSigned) = _calculateAggregatePK(_indexes, _minimumVotingPowerPerTaskDefinition);
        if (_votingPowerSigned < _requiredVotingPower) revert InsufficientVotingPower();
        (bool _callSuccess, bool _result) = BLS.verifySingle(_signature, _aggPubkey, _message);
        if (!_callSuccess || !_result) revert InvalidOBLSSignature();
    }

    function verifyAuthSignature(
        BLSAuthLibrary.Signature calldata _signature,
        address _operator,
        address _contract,
        uint256[4] calldata _blsKey
    ) external view {
        if (!_signature.isValidSignature(_operator, _contract, _blsKey)) revert InvalidAuthSignature();
    }

    function hashToPoint(bytes32 domain, bytes calldata message) external view returns (uint256[2] memory) {
        return BLS.hashToPoint(domain, message);
    }

    function unRegisterOperator(uint256 _index) external onlyOblsManager {
        OBLSStorageData storage _sd = _getStorage();
        _modifyOperatorActiveStatus(_index, false, _sd);
        _resetOperatorVotingPower(_index, _sd);
    }

    function registerOperator(uint256 _index, uint256 _votingPower, uint256[4] memory _blsKey) external onlyOblsManager {
        OBLSStorageData storage _sd = _getStorage();
        _modifyOperatorVotingPower(_index, _votingPower, _sd);
        _modifyOperatorBlsKey(_index, _blsKey, _sd);
        _modifyOperatorActiveStatus(_index, true, _sd);
    }

    function setTotalVotingPowerPerTaskDefinition(uint16 _taskDefinitionId, uint256 _numOfTotalOperators, uint256 _minimumVotingPower) external onlyOblsManager {
        OBLSStorageData storage _sd = _getStorage();
        uint256 _totalVotingPowerPerTaskDefinition;
        for (uint i = 1; i <= _numOfTotalOperators;) {
            BLSOperator memory _operator = _sd.operators[i];
            if(_operator.isActive && _operator.votingPower >= _minimumVotingPower) _totalVotingPowerPerTaskDefinition += _operator.votingPower;
            unchecked {++i;}
        }
        _sd.totalVotingPowerPerTaskDefinition[_taskDefinitionId] = _totalVotingPowerPerTaskDefinition;
    }

    function setTotalVotingPowerPerRestrictedTaskDefinition(uint16 _taskDefinitionId, uint256 _minimumVotingPower, uint256[] calldata _restrictedOperatorIndexes) external onlyOblsManager {
        OBLSStorageData storage _sd = _getStorage();
        uint256 _totalVotingPowerPerTaskDefinition;
        for (uint i = 0; i < _restrictedOperatorIndexes.length;) {
            BLSOperator memory _operator = _sd.operators[_restrictedOperatorIndexes[i]];
            if(_operator.isActive && _operator.votingPower >= _minimumVotingPower) _totalVotingPowerPerTaskDefinition += _operator.votingPower;
            unchecked {++i;}
        }
        _sd.totalVotingPowerPerTaskDefinition[_taskDefinitionId] = _totalVotingPowerPerTaskDefinition;
    }

    function modifyOperatorBlsKey(uint256 _index, uint256[4] memory _blsKey) external onlyOblsManager {
        _modifyOperatorBlsKey(_index, _blsKey, _getStorage());
    }

    // @obsolete - here just for backwards compatibility - use modifyOperatorVotingPower
    function modifyOperatorShares(uint256 _index, uint256 _votingPower) external onlyOblsManager {
        _modifyOperatorVotingPower(_index, _votingPower, _getStorage());
    }

    // @obsolete - here just for backwards compatibility - use increaseOperatorVotingPower
    function increaseOperatorShares(uint256 _index, uint256 _votingPower) external onlyOblsManagerOrSharesSyncer {
        _increaseOperatorVotingPower(_index, _votingPower, _getStorage());
    }

    // @obsolete - here just for backwards compatibility - use increaseBatchOperatorVotingPower
    function increaseBatchOperatorShares(OperatorVotingPower[] memory _operatorUpdateShares) external onlyOblsManagerOrSharesSyncer {
        _increaseBatchOperatorVotingPower(_operatorUpdateShares);
    }

    // @obsolete - here just for backwards compatibility - use decreaseOperatorVotingPower
    function decreaseOperatorShares(uint256 _index, uint256 _votingPower) external onlyOblsManagerOrSharesSyncer {
        _decreaseOperatorVotingPower(_index, _votingPower, _getStorage());
    }

    // @obsolete - here just for backwards compatibility - use decreaseBatchOperatorVotingPower
    function decreaseBatchOperatorShares(OperatorVotingPower[] memory _operatorUpdateShares) external onlyOblsManagerOrSharesSyncer {
        _decreaseBatchOperatorVotingPower(_operatorUpdateShares);
    }

    function modifyOperatorVotingPower(uint256 _index, uint256 _votingPower) external onlyOblsManager {
        _modifyOperatorVotingPower(_index, _votingPower, _getStorage());
    }

    function increaseOperatorVotingPower(uint256 _index, uint256 _votingPower) external onlyOblsManagerOrSharesSyncer {
        _increaseOperatorVotingPower(_index, _votingPower, _getStorage());
    }

    function increaseBatchOperatorVotingPower(OperatorVotingPower[] memory _operatorsVotingPower) external onlyOblsManagerOrSharesSyncer {
        _increaseBatchOperatorVotingPower(_operatorsVotingPower);
    }

    function increaseOperatorVotingPowerPerTaskDefinition(uint16 _taskDefinitionId, uint256 _votingPower) external onlyOblsManagerOrSharesSyncer {
        _increaseOperatorVotingPowerPerTaskDefinition(_taskDefinitionId, _votingPower, _getStorage());
    }

    function decreaseOperatorVotingPower(uint256 _index, uint256 _votingPower) external onlyOblsManagerOrSharesSyncer {
        _decreaseOperatorVotingPower(_index, _votingPower, _getStorage());
    }

    function decreaseBatchOperatorVotingPower(OperatorVotingPower[] memory _operatorsVotingPower) external onlyOblsManagerOrSharesSyncer {
        _decreaseBatchOperatorVotingPower(_operatorsVotingPower);
    }

    function decreaseOperatorVotingPowerPerTaskDefinition(uint16 _taskDefinitionId, uint256 _votingPower) external onlyOblsManagerOrSharesSyncer {
        _decreaseOperatorVotingPowerPerTaskDefinition(_taskDefinitionId, _votingPower, _getStorage());
    }

    function setOblsManager(address _oblsManager) external onlyRole(RolesLibrary.AVS_FACTORY_ROLE) {
        _getStorage().oblsManager = _oblsManager;
    }

    function setOblsSharesSyncer(address _oblsSharesSyncer) external onlyOblsManager {
        _getStorage().oblsSharesSyncer = _oblsSharesSyncer;
        emit SharesSyncerModified(_oblsSharesSyncer);
    }

    function modifyOperatorActiveStatus(uint256 _index, bool _isActive) external onlyOblsManagerOrSharesSyncer {
        _modifyOperatorActiveStatus(_index, _isActive, _getStorage());
    }

    function getOblsManager() external view returns (address) {
        return _getStorage().oblsManager;
    }

    // PRIVATE FUNCTIONS
    function _calculateAggregatePK(uint[] memory _indexes, uint256 _minimumVotingPowerPerTaskDefinition) internal view returns (uint[4] memory _aggPubkey, uint256 _votingPowerSigned) {
        uint _opLength = _indexes.length;
        uint[4][] memory _blsKeys = new uint[4][](_opLength);
        uint _lastSeenOperatorIndex;
        OBLSStorageData storage _oblsStorageData = _getStorage();
        for (uint256 i = 0; i < _opLength; i++) {
            uint _index = _indexes[i];
            if (i != 0 && _lastSeenOperatorIndex >= _index) revert InvalidOperatorIndexes();
            BLSOperator memory _details = _oblsStorageData.operators[_index];
            if(_details.votingPower < _minimumVotingPowerPerTaskDefinition) revert OperatorDoesNotHaveMinimumVotingPower(_index);
            _votingPowerSigned += _details.votingPower;
            if (!_details.isActive) revert InactiveOperator(_index);
            _blsKeys[i] = _details.blsKey;
            _lastSeenOperatorIndex = _index;
        }
        _aggPubkey = _calculateAggregatePKByBlsKeys(_blsKeys);
    }

    function _calculateAggregatePKByBlsKeys(uint[4][] memory _blsKeys) internal view returns (uint[4] memory _aggPubkey) {
        for (uint256 i = 0; i < _blsKeys.length; i++) {
            uint[4] memory _blsKey = _blsKeys[i];
            if (i == 0) {
                _aggPubkey = _blsKey;
            } else {
                _aggPubkey = _buildNextAggPubkey(_aggPubkey, _blsKey);
            }
        }
    }

    function _resetOperatorVotingPower(uint index, OBLSStorageData storage _sd) internal {
        _sd.totalVotingPower -= _sd.operators[index].votingPower;
        delete _sd.operators[index].votingPower;
    }

    function _modifyOperatorVotingPower(uint256 _index, uint256 _votingPower, OBLSStorageData storage _sd) internal {
        _resetOperatorVotingPower(_index, _sd);
        if (_sd.operators[_index].votingPower < _votingPower) {
            _increaseOperatorVotingPower(_index, _votingPower, _sd);
        } else {
            _decreaseOperatorVotingPower(_index, _votingPower, _sd);
        }
    }

    function _increaseOperatorVotingPower(uint256 _index, uint256 _votingPower, OBLSStorageData storage _sd) internal {
        _sd.operators[_index].votingPower += _votingPower;
        _sd.totalVotingPower += _votingPower;
    }

    function _increaseBatchOperatorVotingPower(OperatorVotingPower[] memory _operatorsVotingPower) internal {
        OBLSStorageData storage _sd = _getStorage();
        uint256 _totalVotingPower = _sd.totalVotingPower;
        for (uint256 i = 0; i < _operatorsVotingPower.length; i++) {
            _sd.operators[_operatorsVotingPower[i].operatorId].votingPower += _operatorsVotingPower[i].votingPower;
            _totalVotingPower += _operatorsVotingPower[i].votingPower;       
        }
        _sd.totalVotingPower = _totalVotingPower;
    }

    function _increaseOperatorVotingPowerPerTaskDefinition(uint16 _taskDefinitionId, uint256 _votingPower, OBLSStorageData storage _sd) internal {
        _sd.totalVotingPowerPerTaskDefinition[_taskDefinitionId] += _votingPower;
    }

    function _decreaseOperatorVotingPower(uint256 _index, uint256 _votingPower, OBLSStorageData storage _sd) internal {
        _sd.operators[_index].votingPower -= _votingPower;
        _sd.totalVotingPower -= _votingPower;
    }

    function _decreaseBatchOperatorVotingPower(OperatorVotingPower[] memory _operatorsVotingPower) internal {
        OBLSStorageData storage _sd = _getStorage();
        uint256 _totalVotingPower = _sd.totalVotingPower;
        for (uint256 i = 0; i < _operatorsVotingPower.length; i++) {
            _sd.operators[_operatorsVotingPower[i].operatorId].votingPower -= _operatorsVotingPower[i].votingPower;
            _totalVotingPower -= _operatorsVotingPower[i].votingPower;
        }
        _sd.totalVotingPower = _totalVotingPower;
    }

    function _decreaseOperatorVotingPowerPerTaskDefinition(uint16 _taskDefinitionId, uint256 _votingPower, OBLSStorageData storage _sd) internal {
        _sd.totalVotingPowerPerTaskDefinition[_taskDefinitionId] -= _votingPower;
    }

    function _modifyOperatorBlsKey(uint256 _index, uint256[4] memory _blsKey, OBLSStorageData storage _sd) internal {
        _sd.operators[_index].blsKey = _blsKey;
    }

    function _modifyOperatorActiveStatus(uint256 _index, bool _isActive, OBLSStorageData storage _sd) internal {
        _sd.operators[_index].isActive = _isActive;
    }

    function _buildNextAggPubkey(uint256[4] memory _prevAggPubkey, uint256[4] memory _blsKey) internal view returns (uint256[4] memory nextAggPubkey) {
        uint256[4] memory _nextAggPubkey;
        (
            _nextAggPubkey[0],
            _nextAggPubkey[1],
            _nextAggPubkey[2],
            _nextAggPubkey[3]
        ) = BN256G2.ecTwistAdd(
            _prevAggPubkey[0],
            _prevAggPubkey[1],
            _prevAggPubkey[2],
            _prevAggPubkey[3],
            _blsKey[0],
            _blsKey[1],
            _blsKey[2],
            _blsKey[3]
        );
        return _nextAggPubkey;
    }

    function _getStorage() internal pure returns (OBLSStorageData storage) {
        return OBLSStorage.load();
    }
}
