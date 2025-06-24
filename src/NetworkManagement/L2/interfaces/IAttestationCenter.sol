// SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.19;
/**
 * @author Othentic Labs LTD.
 * @notice Terms of Service: https://www.othentic.xyz/terms-of-service
 */

import {IAvsLogic} from "./IAvsLogic.sol";
import "@othentic/NetworkManagement/Common/interfaces/IOBLS.sol";
import "@othentic/NetworkManagement/L2/TaskDefinitionLibrary.sol";
import {IAccessControl} from "openzeppelin-contracts/contracts/access/IAccessControl.sol";
import "@othentic/NetworkManagement/L2/interfaces/IBeforePaymentsLogic.sol";
import "@othentic/NetworkManagement/L2/interfaces/IInternalTaskHandler.sol";

interface IAttestationCenter is IAccessControl {
    enum OperatorStatus {
        INACTIVE,
        ACTIVE
    }

    enum PaymentStatus {
        REDEEMED,
        COMMITTED,
        CHALLENGED
    }

    struct OperatorDetails {
        address operator;
        uint256 operatorId;
        uint256 votingPower;
        uint256 feeToClaim;
    }

    struct PaymentDetails {
        address operator;
        uint256 lastPaidTaskNumber;
        uint256 feeToClaim;
        PaymentStatus paymentStatus;
    }

    struct PaymentRequestMessage {
        address operator;
        uint256 feeToClaim;
    }

    struct TaskInfo {
        string proofOfTask;
        bytes data;
        address taskPerformer;
        uint16 taskDefinitionId;
    }

    struct TaskSubmissionDetails {
        bool isApproved;
        bytes ecdsaTpSignature;
        uint256[2] blsTpSignature;
        uint256[2] taSignature;
        uint256[] attestersIds;
    }

    struct EcdsaTaskSubmissionDetails {
        bool isApproved;
        bytes tpSignature;
        uint256[2] taSignature;
        uint256[] attestersIds;
    }

    struct BlsTaskSubmissionDetails {
        bool isApproved;
        uint256[2] tpSignature;
        uint256[2] taSignature;
        uint256[] attestersIds;
    }

    struct InitializationParams {
        address avsGovernanceMultisigOwner;
        address operationsMultisig;
        address communityMultisig;
        address messageHandler;
        address obls;
        address avsTreasury;
        bool isRewardsOnL2;
        address internalTaskHandler;
    }

    event OperatorRegisteredToNetwork(address indexed operator, uint256 votingPower);
    event OperatorUnregisteredFromNetwork(uint256 indexed operatorId);
    event PaymentsRequested(PaymentRequestMessage[] operators, uint256 lastPaidTaskNumber);
    event EigenPaymentsRequested(
        uint32 startTimestamp, uint32 duration, PaymentRequestMessage[] operators, uint256 lastPaidTaskNumber
    );
    event ClearPaymentRejected(address indexed operator, uint256 requestedTaskNumber, uint256 requestedAmountClaimed);
    event TaskSubmitted(
        address indexed operator,
        uint32 taskNumber,
        string proofOfTask,
        bytes data,
        uint16 indexed taskDefinitionId,
        uint256[] attestersIds
    );
    event TaskRejected(
        address indexed operator,
        uint32 taskNumber,
        string proofOfTask,
        bytes data,
        uint16 indexed taskDefinitionId,
        uint256[] attestersIds
    );
    event SetMessageHandler(address newMessageHandler);
    event RewardAccumulated(uint256 indexed _operatorId, uint256 _baseRewardFeeForOperator, uint32 indexed _taskNumber);
    event OperatorBlsKeyUpdated(address indexed operator, uint256[4] blsKey);
    event OperatorEjectionRequested(address operator);

    error InvalidOperatorsForPayment();
    error MessageAlreadySigned();
    error InactiveTaskPerformer();
    error InactiveAggregator();
    error InvalidTaskDefinition();
    error TaskDefinitionNotFound(uint16 taskDefinitionId);
    error OperatorNotRegistered(address _operatorAddress);
    error InvalidPerformerSignature();
    error InvalidRangeForBatchPaymentRequest();
    error InvalidRestrictedAttester(uint256 taskDefinitionId, uint256 operatorIndex);
    error InsufficientVotingPowerForTaskDefinition(uint16 taskDefinitionId, uint256 minVotingPower);
    error InvalidAttesterSet();
    error InvalidMaximumNumberOfAttesters();
    error ZeroAddress();
    error NotAnEjector();
    error EigenRewardsNotSupportedOnL2();
    error EigenRewardsMustBeRetroactive();
    error EigenRewardsDurationExceedsMaximum();
    error EigenRewardsDurationNotMultipleOfInterval();
    error EigenRewardsStartTimestampNotMultipleOfInterval();
    error EigenRewardsStartTimestampTooFarInPast();
    error EigenRewardsMaxRewardsAmountExceeded(uint256 totalRewards);

    function taskNumber() external view returns (uint32);

    function numOfActiveOperators() external view returns (uint256);

    function votingPower(address _operator) external view returns (uint256);

    function getOperatorPaymentDetail(uint256 _operatorId) external view returns (PaymentDetails memory);

    function getTaskDefinitionMinimumVotingPower(uint16 _taskDefinitionId) external view returns (uint256);

    function getTaskDefinitionRestrictedAttesters(uint16 _taskDefinitionId) external view returns (uint256[] memory);

    function getTaskDefinitionMaximumNumberOfAttesters(uint16 _taskDefinitionId) external view returns (uint256);

    function numOfTaskDefinitions() external view returns (uint16);

    function operatorsIdsByAddress(address _operator) external view returns (uint256);

    function avsLogic() external view returns (IAvsLogic);

    function beforePaymentsLogic() external view returns (IBeforePaymentsLogic);

    function obls() external view returns (IOBLS);

    function internalTaskHandler() external view returns (IInternalTaskHandler);

    function submitTask(TaskInfo calldata _taskInfo, EcdsaTaskSubmissionDetails calldata _taskSubmissionDetails)
        external;

    function submitTask(TaskInfo calldata _taskInfo, BlsTaskSubmissionDetails calldata _taskSubmissionDetails)
        external;

    function ejectOperatorFromNetwork(address _operator) external;

    function requestBatchPayment() external;

    function requestBatchPayment(uint256 _from, uint256 _to) external;

    function requestEigenBatchPayment(uint32 _startTimestamp, uint32 _duration, uint256 _from, uint256 _to) external;

    function nextEigenRewardsBatchStartTimestamp() external view returns (uint256);

    function registerToNetwork(
        address _operator,
        uint256 _votingPower,
        uint256[4] memory _blsKey,
        address _rewardsReceiver
    ) external;

    function unRegisterOperatorFromNetwork(address _operator) external;

    function clearBatchPayment(PaymentRequestMessage[] memory _operators, uint256 _lastPaidTaskNumber) external;

    function avsTreasury() external view returns (address);

    function getActiveOperatorsDetails() external view returns (OperatorDetails[] memory _operators);
}
