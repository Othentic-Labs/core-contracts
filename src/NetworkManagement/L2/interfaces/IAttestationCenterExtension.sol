// SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.25;
/**
 * @author Othentic Labs LTD.
 * @notice Terms of Service: https://www.othentic.xyz/terms-of-service
 */

import {IAvsLogic} from "./IAvsLogic.sol";
import "@othentic/NetworkManagement/L2/TaskDefinitionLibrary.sol";
import {IAccessControl} from "openzeppelin-contracts/contracts/access/IAccessControl.sol";
import "@othentic/NetworkManagement/L2/interfaces/IBeforePaymentsLogic.sol";
import "@othentic/NetworkManagement/L2/interfaces/IInternalTaskHandler.sol";
import "@othentic/NetworkManagement/L2/interfaces/IFeeCalculator.sol";

interface IAttestationCenterExtension is IAccessControl {
    event SetAvsLogic(address avsLogic);
    event SetBeforePaymentsLogic(address paymentsLogic);
    event SetAvsGovernanceMultisig(address newAvsGovernanceMultisig);
    event SetMessageHandler(address newMessageHandler);
    event SetFeeCalculator(address feeCalculator);
    event SetInternalTaskHandler(address newInternalTaskHandler);
    event SetMinimumTaskDefinitionVotingPower(uint256 minimumVotingPower);
    event SetRestrictedAttester(uint16 indexed taskDefinitionId, uint256[] restrictedAttesterIds);
    event SetMaximumNumberOfAttesters(uint16 indexed taskDefinitionId, uint256 maximumNumberOfAttesters);
    event IsOpenAggregatorSet(bool isOpenAggregator);

    error TaskDefinitionNotFound(uint16 taskDefinitionId);
    error InvalidRestrictedAttester(uint256 taskDefinitionId, uint256 operatorIndex);
    error InvalidRestrictedAttesterIds();
    error InvalidMaximumNumberOfAttesters();
    error ZeroAddress();

    // ------------------ Operations Interface ------------------
    function setOblsSharesSyncer(address _oblsSharesSyncer) external;
    function transferMessageHandler(address _newMessageHandler) external;

    // ------------------ Avs Governance Interface ------------------
    function setAvsLogic(IAvsLogic _avsLogic) external;
    function setBeforePaymentsLogic(IBeforePaymentsLogic _beforePaymentsLogic) external;
    function setInternalTaskHandler(IInternalTaskHandler newInternalTaskHandler) external;
    function setFeeCalculator(IFeeCalculator _feeCalculator) external;
    function setEjector(address _ejector) external;
    function revokeEjector(address _ejector) external;
    function transferAvsGovernanceMultisig(address _newAvsGovernanceMultisig) external;
    function setTaskDefinitionMinVotingPower(uint16 _taskDefinitionId, uint256 _minimumVotingPower) external;
    function setTaskDefinitionRestrictedAttesters(uint16 _taskDefinitionId, uint256[] calldata _restrictedAttesterIds)
        external;
    function setTaskDefinitionMaximumNumberOfAttesters(uint16 _taskDefinitionId, uint256 _maximumNumberOfAttesters)
        external;
    function setIsOpenAggregator(bool _isOpenAggregator) external;
    function createNewTaskDefinition(string memory _name, TaskDefinitionParamsV2 calldata _taskDefinitionParams)
        external
        returns (uint16);
}
