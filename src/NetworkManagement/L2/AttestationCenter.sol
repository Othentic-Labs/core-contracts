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
import "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";

import "@othentic/NetworkManagement/Common/interfaces/IOBLS.sol";
import "@othentic/NetworkManagement/Common/interfaces/IMessageHandler.sol";
import "@othentic/NetworkManagement/Common/OthenticAccessControl.sol";

import "@othentic/NetworkManagement/L2/interfaces/IAttestationCenter.sol";
import "@othentic/NetworkManagement/L2/interfaces/IAvsLogic.sol";
import "@othentic/NetworkManagement/L2/interfaces/IBeforePaymentsLogic.sol";
import "@othentic/NetworkManagement/L2/interfaces/IFeeCalculator.sol";
import "@othentic/NetworkManagement/L2/interfaces/IInternalTaskHandler.sol";
import {IAttestationCenterExtension} from "@othentic/NetworkManagement/L2/interfaces/IAttestationCenterExtension.sol";
import "@othentic/NetworkManagement/L2/TaskDefinitionLibrary.sol";
import "@othentic/NetworkManagement/L2/AttestationCenterStorage.sol";
import "@othentic/NetworkManagement/L2/AttestationCenterPausable.sol";

import {ReentrancyGuardUpgradeable} from
    "openzeppelin-contracts-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";
import {MessagesLibrary} from "@othentic/NetworkManagement/Common/MessagesLibrary.sol";
import {RolesLibrary} from "@othentic/NetworkManagement/Common/RolesLibrary.sol";
import {PauserRolesLibrary} from "@othentic/NetworkManagement/Common/PauserRolesLibrary.sol";
import {BLSAuthLibrary} from "@othentic/NetworkManagement/Common/BLSAuthLibrary.sol";

/**
 * @author Othentic Labs LTD.
 * @notice Terms of Service: https://www.othentic.xyz/terms-of-service
 */
contract AttestationCenter is IAttestationCenter, AttestationCenterPausable, ReentrancyGuardUpgradeable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;
    using TaskDefinitionLibrary for TaskDefinitions;

    bytes32 private constant DOMAIN = keccak256("TasksManager");
    uint32 private constant CALCULATION_INTERVAL_SECONDS = 7 days;
    uint32 private constant MAX_REWARDS_DURATION = 70 days;
    uint32 private constant MAX_RETROACTIVE_LENGTH = 168 days; // @reminder different for testnet
    uint32 private constant GENESIS_REWARDS_TIMESTAMP = 1_710_979_200;
    uint256 private constant MAX_REWARDS_AMOUNT = 1e38 - 1;
    address public immutable EXTENSION_IMPLEMENTATION;

    fallback() external {
        _delegate(EXTENSION_IMPLEMENTATION);
    }

    constructor(address _extensionImplementation) {
        if (_extensionImplementation == address(0)) {
            revert ZeroAddress();
        }
        EXTENSION_IMPLEMENTATION = _extensionImplementation;
    }

    // INITIALIZER
    function initialize(InitializationParams calldata _initializationParams) public initializer {
        _initialize(_initializationParams);
    }

    function _initialize(InitializationParams calldata _initializationParams) internal onlyInitializing {
        address _avsGovernanceMultisigOwner = _initializationParams.avsGovernanceMultisigOwner;
        address _operationsMultisig = _initializationParams.operationsMultisig;
        address _communityMultisig = _initializationParams.communityMultisig;
        address _messageHandler = _initializationParams.messageHandler;
        address _avsTreasury = _initializationParams.avsTreasury;
        if (_avsTreasury == address(0)) revert ZeroAddress();
        __OthenticAccessControl_init(_avsGovernanceMultisigOwner, _operationsMultisig, _communityMultisig);
        __AttestationCenterPausable_init(_avsGovernanceMultisigOwner, _operationsMultisig, _communityMultisig);
        __ReentrancyGuard_init();
        AttestationCenterStorageData storage _sd = _getStorage();
        _sd.taskNumber = 1;
        _sd.obls = IOBLS(_initializationParams.obls);
        _sd.messageHandler = IMessageHandler(_initializationParams.messageHandler);
        _sd.isRewardsOnL2 = _initializationParams.isRewardsOnL2;
        _sd.avsTreasury = IAvsTreasury(_avsTreasury);
        _sd.internalTaskHandler = IInternalTaskHandler(_initializationParams.internalTaskHandler);
        _sd.nextEigenRewardsBatchStartTimestamp = block.timestamp - (block.timestamp % CALCULATION_INTERVAL_SECONDS);
        _grantRole(RolesLibrary.MESSAGE_HANDLER, _messageHandler);
        _setDefaultTaskDefinition(_sd.taskDefinitions.getTaskDefinition(0));
        _setVotingPowerSyncTaskDefinition(
            _sd.taskDefinitions.getTaskDefinition(TaskDefinitionLibrary.VOTING_POWER_SYNC_TASK_DEFINITION_ID)
        );
        _setTotalVotingPowerSyncPerTaskDefinition();
    }

    // ------------------ Operators Interface ------------------

    function submitTask(TaskInfo calldata _taskInfo, EcdsaTaskSubmissionDetails calldata _ecdsaTaskSubmissionDetails)
        external
        whenFlowNotPaused(PauserRolesLibrary.TASKS_SUBMISSION_FLOW)
        nonReentrant
    {
        TaskSubmissionDetails memory _taskSubmissionDetails = TaskSubmissionDetails({
            isApproved: _ecdsaTaskSubmissionDetails.isApproved,
            ecdsaTpSignature: _ecdsaTaskSubmissionDetails.tpSignature,
            blsTpSignature: [uint256(0), uint256(0)],
            taSignature: _ecdsaTaskSubmissionDetails.taSignature,
            attestersIds: _ecdsaTaskSubmissionDetails.attestersIds
        });
        _submitTask(_taskInfo, _taskSubmissionDetails);
    }

    function submitTask(TaskInfo calldata _taskInfo, BlsTaskSubmissionDetails calldata _blsTaskSubmissionDetails)
        external
        whenFlowNotPaused(PauserRolesLibrary.TASKS_SUBMISSION_FLOW)
        nonReentrant
    {
        TaskSubmissionDetails memory _taskSubmissionDetails = TaskSubmissionDetails({
            isApproved: _blsTaskSubmissionDetails.isApproved,
            ecdsaTpSignature: "",
            blsTpSignature: _blsTaskSubmissionDetails.tpSignature,
            taSignature: _blsTaskSubmissionDetails.taSignature,
            attestersIds: _blsTaskSubmissionDetails.attestersIds
        });
        _submitTask(_taskInfo, _taskSubmissionDetails);
    }

    function updateBlsKey(uint256[4] calldata _blsKey, BLSAuthLibrary.Signature calldata _authSignature) external {
        AttestationCenterStorageData storage _sd = _getStorage();
        address _operator = msg.sender;
        uint256 _operatorId = _getOperatorId(_sd, _operator);
        IOBLS _obls = _sd.obls;
        _obls.verifyAuthSignature(_authSignature, _operator, address(this), _blsKey);
        _obls.modifyOperatorBlsKey(_operatorId, _blsKey);
        emit OperatorBlsKeyUpdated(_operator, _blsKey);
    }

    function obls() external view returns (IOBLS) {
        return _getStorage().obls;
    }

    function avsTreasury() external view returns (address) {
        return address(_getStorage().avsTreasury);
    }

    function votingPower(address _operator) external view returns (uint256) {
        AttestationCenterStorageData storage _sd = _getStorage();
        uint256 _operatorId = _getOperatorId(_sd, _operator);
        return _sd.obls.votingPower(_operatorId);
    }

    function verifyOperatorValidForTaskDefinition(address _operator, uint16 _taskDefinitionId) external view {
        AttestationCenterStorageData storage _sd = _getStorage();
        uint256 _operatorId = _getOperatorId(_sd, _operator);
        TaskDefinition memory _taskDefinition = _getTaskDefinition(_sd, _taskDefinitionId);
        uint256[] memory _operatorIds = new uint256[](1);
        _operatorIds[0] = _operatorId;
        _verifyTaskDefinition(_taskDefinition, _operatorIds);
        if (_sd.obls.votingPower(_operatorId) < _taskDefinition.minimumVotingPower) {
            revert InsufficientVotingPowerForTaskDefinition(_taskDefinitionId, _taskDefinition.minimumVotingPower);
        }
    }

    function operatorsIdsByAddress(address _operator) external view returns (uint256) {
        return _getOperatorId(_getStorage(), _operator);
    }

    function taskNumber() external view returns (uint32) {
        return _getStorage().taskNumber;
    }

    function avsLogic() external view returns (IAvsLogic) {
        return _getStorage().avsLogic;
    }

    function beforePaymentsLogic() external view returns (IBeforePaymentsLogic) {
        return _getStorage().beforePaymentsLogic;
    }

    function internalTaskHandler() external view returns (IInternalTaskHandler) {
        return _getStorage().internalTaskHandler;
    }

    function numOfActiveOperators() external view returns (uint256) {
        return _getStorage().numOfActiveOperators;
    }

    function getOperatorPaymentDetail(uint256 _operatorId) external view returns (PaymentDetails memory) {
        return _getStorage().operators[_operatorId];
    }

    function getTaskDefinitionMinimumVotingPower(uint16 _taskDefinitionId) external view returns (uint256) {
        return _getStorage().taskDefinitions.getMinimumVotingPower(_taskDefinitionId);
    }

    function getTaskDefinitionRestrictedAttesters(uint16 _taskDefinitionId) external view returns (uint256[] memory) {
        return _getStorage().taskDefinitions.getRestrictedAttesterIds(_taskDefinitionId);
    }

    function getTaskDefinitionMaximumNumberOfAttesters(uint16 _taskDefinitionId) external view returns (uint256) {
        return _getStorage().taskDefinitions.getMaximumNumberOfAttesters(_taskDefinitionId);
    }

    function numOfTaskDefinitions() external view returns (uint16) {
        return _getStorage().taskDefinitions.counter;
    }

    /// @dev Including unregistered operators
    function numOfTotalOperators() external view returns (uint256) {
        return _getStorage().numOfTotalOperators;
    }

    function getActiveOperatorsDetails() external view returns (OperatorDetails[] memory _operators) {
        AttestationCenterStorageData storage _sd = _getStorage();
        IOBLS _obls = _sd.obls;
        _operators = new OperatorDetails[](_sd.numOfActiveOperators);
        uint256 _index = 0;
        for (uint256 i = 1; i <= _sd.numOfTotalOperators; i++) {
            if (_obls.isActive(i)) {
                PaymentDetails memory operator = _sd.operators[i];
                _operators[_index] = (
                    OperatorDetails({
                        operator: operator.operator,
                        operatorId: i,
                        votingPower: _obls.votingPower(i),
                        feeToClaim: operator.feeToClaim
                    })
                );
                _index++;
            }
        }
    }

    // ------------------ Layer 1 Interface ------------------

    function registerToNetwork(
        address _operator,
        uint256 _votingPower,
        uint256[4] memory _blsKey,
        address _rewardsReceiver
    ) external onlyRole(RolesLibrary.MESSAGE_HANDLER) {
        AttestationCenterStorageData storage _sd = _getStorage();
        uint256 _operatorIndex = ++_sd.numOfTotalOperators;
        uint256 _feeToClaim = 0;
        uint256 _previousOperatorId = _sd.operatorsIdsByAddress[_operator];
        uint256 _lastPaidTaskNumber = 0;
        PaymentStatus _paymentStatus = PaymentStatus.REDEEMED;
        if (_previousOperatorId != 0) {
            PaymentDetails storage _previousDetails = _sd.operators[_previousOperatorId];
            _feeToClaim = _previousDetails.feeToClaim;
            _previousDetails.feeToClaim = 0;
            _paymentStatus = _previousDetails.paymentStatus;
            _lastPaidTaskNumber = _previousDetails.lastPaidTaskNumber;
        }
        ++_sd.numOfActiveOperators;
        _sd.operators[_operatorIndex] = PaymentDetails({
            operator: _operator,
            feeToClaim: _feeToClaim,
            paymentStatus: _paymentStatus,
            lastPaidTaskNumber: _lastPaidTaskNumber
        });
        _sd.operatorsIdsByAddress[_operator] = _operatorIndex;
        _sd.rewardsReceiver[_operator] = _rewardsReceiver;
        _sd.obls.registerOperator(_operatorIndex, _votingPower, _blsKey);
        emit OperatorRegisteredToNetwork(_operator, _votingPower);
    }

    function unRegisterOperatorFromNetwork(address _operator) external onlyRole(RolesLibrary.MESSAGE_HANDLER) {
        AttestationCenterStorageData storage _sd = _getStorage();
        IOBLS _obls = _sd.obls;
        uint256 _operatorId = _getOperatorId(_sd, _operator);
        --_sd.numOfActiveOperators;
        _obls.unRegisterOperator(_operatorId);
        emit OperatorUnregisteredFromNetwork(_operatorId);
    }

    function clearBatchPayment(PaymentRequestMessage[] memory _operators, uint256 _paidTaskNumber)
        external
        onlyRole(RolesLibrary.MESSAGE_HANDLER)
    {
        AttestationCenterStorageData storage _sd = _getStorage();

        for (uint256 i = 0; i < _operators.length && _operators[i].operator != address(0); i++) {
            PaymentRequestMessage memory _paymentRequestMessage = _operators[i];
            uint256 _operatorId = _sd.operatorsIdsByAddress[_paymentRequestMessage.operator];
            _redeemPayment(_sd.operators[_operatorId], _paidTaskNumber, _paymentRequestMessage.feeToClaim);
        }
    }

    // ------------------ Avs Governance Interface ------------------

    function requestBatchPayment()
        external
        whenFlowNotPaused(PauserRolesLibrary.BATCH_PAYMENT_REQUEST_FLOW)
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
    {
        AttestationCenterStorageData storage _sd = _getStorage();
        _requestBatchPayment(_sd, 1, _sd.numOfTotalOperators);
    }

    function requestBatchPayment(uint256 _from, uint256 _to)
        external
        whenFlowNotPaused(PauserRolesLibrary.BATCH_PAYMENT_REQUEST_FLOW)
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
    {
        _requestBatchPayment(_getStorage(), _from, _to);
    }

    function nextEigenRewardsBatchStartTimestamp() external view returns (uint256) {
        return _getStorage().nextEigenRewardsBatchStartTimestamp;
    }

    function requestEigenBatchPayment(uint32 _startTimestamp, uint32 _duration, uint256 _from, uint256 _to)
        external
        whenFlowNotPaused(PauserRolesLibrary.EIGEN_PAYMENT_REQUEST_FLOW)
        onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG)
    {
        AttestationCenterStorageData storage _sd = _getStorage();

        if (_sd.isRewardsOnL2) {
            revert EigenRewardsNotSupportedOnL2();
        }
        _validateTimeRange(_startTimestamp, _duration);

        (PaymentRequestMessage[] memory _operators, uint256 _lastIndex, uint256 _totalRewards) =
            _collectEligibleOperators(_sd, _from, _to);
        if (_totalRewards > MAX_REWARDS_AMOUNT) revert EigenRewardsMaxRewardsAmountExceeded(_totalRewards);

        if (_lastIndex > 0) {
            // Sort operators for Eigen
            if (_lastIndex > 1) {
                for (uint256 j = 0; j < _lastIndex - 1; j++) {
                    for (uint256 k = 0; k < _lastIndex - j - 1; k++) {
                        if (uint160(_operators[k].operator) > uint160(_operators[k + 1].operator)) {
                            (_operators[k], _operators[k + 1]) = (_operators[k + 1], _operators[k]);
                        }
                    }
                }
            }

            bytes memory _rewardsData = abi.encode(_startTimestamp, _duration, _totalRewards, _lastIndex);

            assembly {
                mstore(_operators, _lastIndex)
            }

            _triggerL1EigenRewardsRequest(_sd, _operators, _rewardsData);
            emit EigenPaymentsRequested(_startTimestamp, _duration, _operators, _sd.taskNumber);
        } else {
            revert InvalidOperatorsForPayment();
        }
        _sd.nextEigenRewardsBatchStartTimestamp = _startTimestamp + _duration;
    }

    function setOblsSharesSyncer(address _oblsSharesSyncer) external onlyRole(RolesLibrary.AVS_GOVERNANCE_MULTISIG) {
        _getStorage().obls.setOblsSharesSyncer(_oblsSharesSyncer);
    }

    // ------------------ Ejector Interface ------------------
    function ejectOperatorFromNetwork(address _operator) external onlyRole(RolesLibrary.EJECTOR) {
        AttestationCenterStorageData storage _sd = _getStorage();
        uint256 _operatorId = _getOperatorId(_sd, _operator);
        IOBLS _obls = _sd.obls;
        if (!_obls.isActive(_operatorId)) revert OperatorNotRegistered(_operator);
        _triggerL1OperatorEjection(_sd, _operator);
        emit OperatorEjectionRequested(_operator);
    }

    // PRIVATE FUNCTIONS

    // @dev can change memory back to calldata after ecdsa submit Task is removed
    function _submitTask(TaskInfo calldata _taskInfo, TaskSubmissionDetails memory _taskSubmissionDetails) internal {
        bool _isInternal = _taskInfo.taskDefinitionId >= TaskDefinitionLibrary.MIN_INTERNAL_TASK_ID;
        bool _isBls = _taskSubmissionDetails.blsTpSignature[0] != 0;
        AttestationCenterStorageData storage _sd = _getStorage();
        IAvsLogic _avsLogic = _sd.avsLogic;
        bool _isAvsLogicSet = address(_avsLogic) != address(0) && !_isInternal;
        if (_isAvsLogicSet) {
            if (_isBls) {
                _avsLogic.beforeTaskSubmission(
                    _taskInfo,
                    _taskSubmissionDetails.isApproved,
                    _taskSubmissionDetails.blsTpSignature,
                    _taskSubmissionDetails.taSignature,
                    _taskSubmissionDetails.attestersIds
                );
            } else {
                _avsLogic.beforeTaskSubmission(
                    _taskInfo,
                    _taskSubmissionDetails.isApproved,
                    _taskSubmissionDetails.ecdsaTpSignature,
                    _taskSubmissionDetails.taSignature,
                    _taskSubmissionDetails.attestersIds
                );
            }
        }
        bytes32 _taskHash = keccak256(
            abi.encode(_taskInfo.proofOfTask, _taskInfo.data, _taskInfo.taskPerformer, _taskInfo.taskDefinitionId)
        );
        if (_sd.signedTasks[_taskHash]) revert MessageAlreadySigned();
        IOBLS _obls = _sd.obls;
        if (_isBls) {
            uint256[2] memory _taskMessage = _obls.hashToPoint(DOMAIN, abi.encode(_taskHash));
            _obls.validateOperatorSignature(
                _getOperatorId(_sd, _taskInfo.taskPerformer), _taskMessage, _taskSubmissionDetails.blsTpSignature
            );
        } else {
            _validatePerformerSignature(_taskInfo.taskPerformer, _taskHash, _taskSubmissionDetails.ecdsaTpSignature);
        }
        uint256[2] memory _message =
            _obls.hashToPoint(DOMAIN, abi.encode(_hashVote(_taskInfo, _taskSubmissionDetails.isApproved)));
        TaskDefinition memory _taskDefinition;
        _taskDefinition = _getTaskDefinition(_sd, _taskInfo.taskDefinitionId);
        _verifyTaskDefinition(_taskDefinition, _taskSubmissionDetails.attestersIds);

        _verifyAggregatedSignature(
            _obls,
            _taskSubmissionDetails.isApproved,
            _taskInfo.taskDefinitionId,
            _taskDefinition,
            _taskSubmissionDetails.taSignature,
            _taskSubmissionDetails.attestersIds,
            _message
        );
        _submitTaskBusinessLogic(
            _sd, _taskInfo, _taskDefinition, _taskSubmissionDetails.isApproved, _taskSubmissionDetails.attestersIds
        );
        _sd.signedTasks[_taskHash] = true;
        if (_isAvsLogicSet) {
            if (_isBls) {
                _avsLogic.afterTaskSubmission(
                    _taskInfo,
                    _taskSubmissionDetails.isApproved,
                    _taskSubmissionDetails.blsTpSignature,
                    _taskSubmissionDetails.taSignature,
                    _taskSubmissionDetails.attestersIds
                );
            } else {
                _avsLogic.afterTaskSubmission(
                    _taskInfo,
                    _taskSubmissionDetails.isApproved,
                    _taskSubmissionDetails.ecdsaTpSignature,
                    _taskSubmissionDetails.taSignature,
                    _taskSubmissionDetails.attestersIds
                );
            }
        } else if (_isInternal && _taskSubmissionDetails.isApproved) {
            _sd.internalTaskHandler.processTask(_taskInfo);
        }
    }

    function _submitTaskBusinessLogic(
        AttestationCenterStorageData storage _sd,
        TaskInfo calldata _taskInfo,
        TaskDefinition memory _taskDefinition,
        bool _isApproved,
        uint256[] memory _attestersIds
    ) private {
        uint32 _taskNumber = _sd.taskNumber;
        if (_isApproved) {
            emit TaskSubmitted(
                _taskInfo.taskPerformer,
                _taskNumber,
                _taskInfo.proofOfTask,
                _taskInfo.data,
                _taskInfo.taskDefinitionId,
                _attestersIds
            );
        } else {
            emit TaskRejected(
                _taskInfo.taskPerformer,
                _taskNumber,
                _taskInfo.proofOfTask,
                _taskInfo.data,
                _taskInfo.taskDefinitionId,
                _attestersIds
            );
        }

        uint256 _taskPerformerId = _getOperatorId(_sd, _taskInfo.taskPerformer);
        uint256 _aggregatorId = _getAggregatorId(_sd);
        bool _isOpenAggregator = _sd.isOpenAggregator;
        {
            IOBLS _obls = _sd.obls;
            if (!_obls.isActive(_taskPerformerId)) revert InactiveTaskPerformer();
            if (!_isOpenAggregator && !_obls.isActive(_aggregatorId)) revert InactiveAggregator();
        }
        IFeeCalculator.FeeCalculatorData memory _feeCalculatorData =
            IFeeCalculator.FeeCalculatorData(_taskInfo, _aggregatorId, _taskPerformerId, _attestersIds, _isApproved);

        IFeeCalculator _feeCalculator = _sd.feeCalculator;
        bool _isFeeCalculatorSet = address(_feeCalculator) != address(0);
        if (!_isFeeCalculatorSet || (_isFeeCalculatorSet && _feeCalculator.isBaseRewardFee())) {
            (
                uint256 _baseRewardFeeForAttesters,
                uint256 _baseRewardFeeForPerformer,
                uint256 _baseRewardFeeForAggregator
            ) = _calculateBaseRewardFees(_sd, _taskDefinition, _feeCalculatorData);
            _accumulateRewardsForOperators(_sd, _baseRewardFeeForAttesters, _attestersIds, _taskNumber);
            if (_isApproved) {
                _accumulateRewardsForOperator(_sd, _baseRewardFeeForPerformer, _taskPerformerId, _taskNumber);
            }
            if (!_isOpenAggregator) {
                _accumulateRewardsForOperator(_sd, _baseRewardFeeForAggregator, _aggregatorId, _taskNumber);
            }
        } else {
            IFeeCalculator.FeePerId[] memory _feesPerId = _feeCalculator.calculateFeesPerId(_feeCalculatorData);
            _accumulateRewardsForOperatorsById(_sd, _feesPerId, _taskNumber);
        }
        _sd.taskNumber++;
    }

    function _accumulateRewardsForOperatorsById(
        AttestationCenterStorageData storage _sd,
        IFeeCalculator.FeePerId[] memory _feesPerId,
        uint32 _taskNumber
    ) private {
        for (uint256 i = 0; i < _feesPerId.length; i++) {
            uint256 _operatorId = _feesPerId[i].index;
            uint256 _feeToClaim = _feesPerId[i].fee;
            _accumulateRewardsForOperator(_sd, _feeToClaim, _operatorId, _taskNumber);
        }
    }

    function _calculateBaseRewardFees(
        AttestationCenterStorageData storage _sd,
        TaskDefinition memory _taskDefinition,
        IFeeCalculator.FeeCalculatorData memory _feeCalculatorData
    )
        private
        returns (
            uint256 _baseRewardFeeForAttesters,
            uint256 _baseRewardFeeForPerformer,
            uint256 _baseRewardFeeForAggregator
        )
    {
        IFeeCalculator _feeCalculator = _sd.feeCalculator;
        bool _isFeeCalculatorSet = address(_feeCalculator) != address(0);
        if (_isFeeCalculatorSet) {
            (_baseRewardFeeForAttesters, _baseRewardFeeForPerformer, _baseRewardFeeForAggregator) =
                _feeCalculator.calculateBaseRewardFees(_feeCalculatorData);
        } else {
            _baseRewardFeeForAttesters = _taskDefinition.baseRewardFeeForAttesters;
            _baseRewardFeeForPerformer = _taskDefinition.baseRewardFeeForPerformer;
            _baseRewardFeeForAggregator = _taskDefinition.baseRewardFeeForAggregator;
        }
    }

    function _accumulateRewardsForOperators(
        AttestationCenterStorageData storage _sd,
        uint256 _baseRewardFeeForOperators,
        uint256[] memory _attestersIds,
        uint32 _taskNumber
    ) private {
        for (uint256 i = 0; i < _attestersIds.length; i++) {
            _accumulateRewardsForOperator(_sd, _baseRewardFeeForOperators, _attestersIds[i], _taskNumber);
        }
    }

    function _accumulateRewardsForOperator(
        AttestationCenterStorageData storage _sd,
        uint256 _baseRewardFeeForOperator,
        uint256 _operatorId,
        uint32 _taskNumber
    ) private {
        _sd.operators[_operatorId].feeToClaim += _baseRewardFeeForOperator;
        emit RewardAccumulated(_operatorId, _baseRewardFeeForOperator, _taskNumber);
    }

    function _setVotingPowerSyncTaskDefinition(TaskDefinition storage _defaultTaskDefinition) private {
        _defaultTaskDefinition.name = "Voting Power Sync Task";
        _defaultTaskDefinition.taskDefinitionId = TaskDefinitionLibrary.VOTING_POWER_SYNC_TASK_DEFINITION_ID;
        _defaultTaskDefinition.blockExpiry = type(uint256).max;
    }

    function _setTotalVotingPowerSyncPerTaskDefinition() private {
        AttestationCenterStorageData storage _sd = _getStorage();
        TaskDefinition storage _defaultTaskDefinition =
            _sd.taskDefinitions.getTaskDefinition(TaskDefinitionLibrary.TOTAL_VOTING_POWER_CALC_TASK_DEFINITION_ID);
        _defaultTaskDefinition.name = "Total Voting Power Sync Task Definition";
        _defaultTaskDefinition.taskDefinitionId = TaskDefinitionLibrary.TOTAL_VOTING_POWER_CALC_TASK_DEFINITION_ID;
        _defaultTaskDefinition.blockExpiry = type(uint256).max;
    }

    function _triggerL1OperatorEjection(AttestationCenterStorageData storage _sd, address _operator) private {
        bytes memory _ejectionMessage = MessagesLibrary.BuildOperatorEjectionMessage(_operator);
        _sd.messageHandler.sendMessage(_ejectionMessage);
    }

    function _triggerL1BatchPaymentRequest(
        AttestationCenterStorageData storage _sd,
        PaymentRequestMessage[] memory _operators
    ) internal {
        bytes memory _paymentMessage =
            MessagesLibrary.BuildBatchPaymentRequestMessage(abi.encode(_operators), _sd.taskNumber);
        _sd.messageHandler.sendMessage(_paymentMessage);
    }

    function _triggerL1EigenRewardsRequest(
        AttestationCenterStorageData storage _sd,
        PaymentRequestMessage[] memory _operators,
        bytes memory _rewardsData
    ) internal {
        bytes memory _paymentMessage =
            MessagesLibrary.BuildEigenRewardsRequestMessage(abi.encode(_operators), _sd.taskNumber, _rewardsData);
        _sd.messageHandler.sendMessage(_paymentMessage);
    }

    /// @dev Constraints enforced by EigenLayer's RewardCoordinator contract
    ///      https://github.com/Layr-Labs/eigenlayer-contracts/blob/ecaff6304de6cb0f43b42024ad55d0e8a0430790/src/contracts/core/RewardsCoordinator.sol#L414
    function _validateTimeRange(uint32 _startTimestamp, uint32 _duration) internal view {
        if (_duration > MAX_REWARDS_DURATION) {
            revert EigenRewardsDurationExceedsMaximum();
        }

        if (_duration % CALCULATION_INTERVAL_SECONDS != 0) {
            revert EigenRewardsDurationNotMultipleOfInterval();
        }

        if (_startTimestamp % CALCULATION_INTERVAL_SECONDS != 0) {
            revert EigenRewardsStartTimestampNotMultipleOfInterval();
        }

        if (
            _startTimestamp < uint32(block.timestamp) - MAX_RETROACTIVE_LENGTH
                || _startTimestamp < GENESIS_REWARDS_TIMESTAMP
        ) {
            revert EigenRewardsStartTimestampTooFarInPast();
        }

        if (_startTimestamp + _duration > block.timestamp) {
            revert EigenRewardsMustBeRetroactive();
        }
    }

    function _setDefaultTaskDefinition(TaskDefinition storage _defaultTaskDefinition) internal {
        _defaultTaskDefinition.name = "default";
        _defaultTaskDefinition.blockExpiry = type(uint256).max;
        _defaultTaskDefinition.baseRewardFeeForAttesters = 10 ** 19;
        _defaultTaskDefinition.baseRewardFeeForPerformer = 10 ** 19;
        _defaultTaskDefinition.baseRewardFeeForAggregator = 10 ** 19;
    }

    function _redeemPayment(PaymentDetails storage _details, uint256 _paidTaskNumber, uint256 _amountClaimed) private {
        if (_isValidPaymentRequest(_details, _paidTaskNumber, _amountClaimed)) {
            if (_amountClaimed > 0) {
                _details.lastPaidTaskNumber = _paidTaskNumber;
                _details.feeToClaim -= _amountClaimed;
            }
            _details.paymentStatus = PaymentStatus.REDEEMED;
        } else {
            emit ClearPaymentRejected(_details.operator, _paidTaskNumber, _amountClaimed);
        }
    }

    function _withdrawL2Rewards(
        AttestationCenterStorageData storage _sd,
        PaymentDetails storage _details,
        uint32 _taskNumber,
        IAvsTreasury _l2AvsTreasury
    ) private {
        address _tmpRewardsReceiver = _sd.rewardsReceiver[_details.operator];
        address _rewardsReceiver = _tmpRewardsReceiver == address(0) ? _details.operator : _tmpRewardsReceiver;
        bool _success = _l2AvsTreasury.withdrawRewards(_rewardsReceiver, _taskNumber, _details.feeToClaim);
        uint256 _feeToClaim = 0;
        if (_success) _feeToClaim = _details.feeToClaim;
        _redeemPayment(_details, _taskNumber, _feeToClaim);
    }

    function _requestBatchPayment(AttestationCenterStorageData storage _sd, uint256 _from, uint256 _to) private {
        (PaymentRequestMessage[] memory _operators, uint256 _lastIndex, /* uint256 _totalRewards */ ) =
            _collectEligibleOperators(_sd, _from, _to);

        if (_lastIndex == 0) revert InvalidOperatorsForPayment();
        if (!_sd.isRewardsOnL2) {
            _triggerL1BatchPaymentRequest(_sd, _operators);
        }
        emit PaymentsRequested(_operators, _sd.taskNumber);
    }

    function _collectEligibleOperators(AttestationCenterStorageData storage _sd, uint256 _from, uint256 _to)
        private
        returns (PaymentRequestMessage[] memory, uint256, uint256)
    {
        if (_from == 0 || _to > _sd.numOfTotalOperators || _from > _to) revert InvalidRangeForBatchPaymentRequest();
        uint32 _taskNumber = _sd.taskNumber;
        PaymentRequestMessage[] memory _operators = new PaymentRequestMessage[](_to - _from + 1);
        uint256 _lastIndex = 0;
        uint256 _totalRewards;
        for (uint256 i = _from; i <= _to;) {
            PaymentDetails storage _details = _sd.operators[i];
            if (
                _details.operator != address(0) && _details.paymentStatus == PaymentStatus.REDEEMED
                    && _details.lastPaidTaskNumber < _taskNumber && _details.feeToClaim > 0
            ) {
                _operators[_lastIndex] = PaymentRequestMessage(_details.operator, _details.feeToClaim);
                _details.paymentStatus = PaymentStatus.COMMITTED;
                _lastIndex++;
                _totalRewards += _details.feeToClaim;
                if (_sd.isRewardsOnL2) {
                    _withdrawL2Rewards(_sd, _details, _taskNumber, _sd.avsTreasury);
                }
            }
            unchecked {
                ++i;
            }
        }

        return (_operators, _lastIndex, _totalRewards);
    }

    // PRIVATE VIEWS FUNCTIONS

    function _verifyAggregatedSignature(
        IOBLS _obls,
        bool _isApproved,
        uint16 _taskDefinitionId,
        TaskDefinition memory _taskDefinition,
        uint256[2] memory _signature,
        uint256[] memory _attestersIds,
        uint256[2] memory _message
    ) private view {
        uint256 _requriedVotingPower =
            _getRequriedVotingPowerByApprovalStatus(_obls, _isApproved, _taskDefinitionId, _taskDefinition);
        _obls.verifySignature(
            _message, _signature, _attestersIds, _requriedVotingPower, _taskDefinition.minimumVotingPower
        );
    }

    function _getOperatorId(AttestationCenterStorageData storage _sd, address _operatorAddress)
        private
        view
        returns (uint256)
    {
        IOBLS _obls = _sd.obls;
        uint256 _operatorId = _sd.operatorsIdsByAddress[_operatorAddress];
        if (_operatorId == 0 || !_obls.isActive(_operatorId)) revert OperatorNotRegistered(_operatorAddress);
        return _operatorId;
    }

    function _getAggregatorId(AttestationCenterStorageData storage _sd) private view returns (uint256) {
        uint256 _aggregatorId = 0;
        if (!_sd.isOpenAggregator) _aggregatorId = _getOperatorId(_sd, msg.sender);
        return _aggregatorId;
    }

    function _getRequriedVotingPowerByApprovalStatus(
        IOBLS _obls,
        bool _isApproved,
        uint16 _taskDefinitionId,
        TaskDefinition memory _taskDefinition
    ) private view returns (uint256) {
        uint256 _totalVotingPower;
        if (_taskDefinition.restrictedAttesterIds.length > 0 || _taskDefinition.minimumVotingPower > 0) {
            _totalVotingPower = _obls.totalVotingPowerPerTaskDefinition(_taskDefinitionId);
        } else {
            _totalVotingPower = _obls.totalVotingPower();
        }
        if (_isApproved) {
            return _totalVotingPower * 2 / 3;
        } else {
            return _totalVotingPower * 1 / 3;
        }
    }

    function _isValidPaymentRequest(PaymentDetails storage _details, uint256 _paidTaskNumber, uint256 _amountClaimed)
        private
        view
        returns (bool)
    {
        if (_details.paymentStatus != PaymentStatus.COMMITTED) {
            return false;
        }
        if (_details.lastPaidTaskNumber >= _paidTaskNumber) {
            return false;
        }
        if (_details.feeToClaim < _amountClaimed) {
            return false;
        }
        return true;
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

    function _verifyTaskDefinition(TaskDefinition memory _taskDefinition, uint256[] memory _attesterIndexes)
        private
        view
    {
        if (_taskDefinition.blockExpiry <= block.number) revert InvalidTaskDefinition();
        uint256[] memory _restrictedAttesterIds = _taskDefinition.restrictedAttesterIds;
        if (_restrictedAttesterIds.length > 0) {
            if (_restrictedAttesterIds.length < _attesterIndexes.length) revert InvalidAttesterSet();
            uint256 _invalidIndex = _verifyArraySubset(_attesterIndexes, _restrictedAttesterIds);
            if (_invalidIndex > 0) revert InvalidRestrictedAttester(_taskDefinition.taskDefinitionId, _invalidIndex);
        }
        if (
            _taskDefinition.maximumNumberOfAttesters > 0
                && _taskDefinition.maximumNumberOfAttesters < _attesterIndexes.length
        ) revert InvalidMaximumNumberOfAttesters();
    }
    // PRIVATE PURE FUNCTIONS

    function _verifyArraySubset(uint256[] memory _arr1, uint256[] memory _arr2) private pure returns (uint256) {
        uint256 i = 0;
        uint256 j = 0;
        while (i < _arr1.length && j < _arr2.length) {
            if (_arr1[i] == _arr2[j]) {
                i++;
                j++;
            } else if (_arr1[i] > _arr2[j]) {
                j++;
            } else {
                return _arr1[i];
            }
        }
        if (i == _arr1.length) {
            return 0;
        } else {
            return _arr1[i];
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

    function _validatePerformerSignature(address _taskPerformer, bytes32 _taskHash, bytes memory _tpSignature)
        private
        pure
    {
        address _recoveredPerformer = _taskHash.recover(_tpSignature);
        if (_recoveredPerformer != _taskPerformer) revert InvalidPerformerSignature();
    }

    function _hashVote(TaskInfo calldata _taskInfo, bool _isApproved) private view returns (bytes32) {
        return keccak256(
            abi.encode(
                _taskInfo.proofOfTask,
                _taskInfo.data,
                _taskInfo.taskPerformer,
                _taskInfo.taskDefinitionId,
                address(this),
                block.chainid,
                _isApproved
            )
        );
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

    function _getStorage() internal pure returns (AttestationCenterStorageData storage _sd) {
        return AttestationCenterStorage.load();
    }
}
