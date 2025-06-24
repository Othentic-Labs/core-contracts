// SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.19;
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

import {MessageHandler} from "@othentic/NetworkManagement/Common/MessageHandler.sol";
import {MessageHandlerStorageData} from "@othentic/lz/v2/oapp/MessageHandlerStorage.sol";
import {
    ILayerZeroEndpointV2,
    Origin
} from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import {IAvsGovernance} from "@othentic/NetworkManagement/L1/interfaces/IAvsGovernance.sol";
import {IAvsGovernanceExtension} from "@othentic/NetworkManagement/L1/interfaces/IAvsGovernanceExtension.sol";
import {IL1MessageHandler} from "@othentic/NetworkManagement/L1/interfaces/IL1MessageHandler.sol";
import {
    L1MessageHandlerStorage,
    L1MessageHandlerStorageData
} from "@othentic/NetworkManagement/L1/L1MessageHandlerStorage.sol";
import {MessagesLibrary} from "@othentic/NetworkManagement/Common/MessagesLibrary.sol";
import {RolesLibrary} from "@othentic/NetworkManagement/Common/RolesLibrary.sol";
import {IRewardsCoordinator} from "@eigenlayer/contracts/interfaces/IRewardsCoordinator.sol";
/**
 * @author Othentic Labs LTD.
 * @notice Terms of Service: https://www.othentic.xyz/terms-of-service
 */

contract L1MessageHandler is MessageHandler, IL1MessageHandler {
    // INITIALIZER
    function initialize(
        address _avsGovernanceMultisigOwner,
        address _operationsMultisig,
        address _communityMultisig,
        address _lzEndpoint,
        uint32 _lzEid,
        address _factoryAddress,
        uint32[] memory _lzEids
    ) public initializer {
        L1MessageHandlerStorageData storage _sd = _getL1MessageHandlerStorage();
        _initialize(
            _avsGovernanceMultisigOwner, _operationsMultisig, _communityMultisig, _lzEndpoint, _lzEid, _factoryAddress
        );
        _sd.lzEids = _lzEids;
    }

    // -------------------- Getters ------------------------------------------ //
    function getLzEids() external view returns (uint32[] memory) {
        return _getL1MessageHandlerStorage().lzEids;
    }

    // -------------------- Operations Multisig Interface -------------------- //

    function transferAvsGovernance(address _newAvsGovernance) external onlyRole(RolesLibrary.OPERATIONS_MULTISIG) {
        L1MessageHandlerStorageData storage _sd = _getL1MessageHandlerStorage();
        _revokeRole(RolesLibrary.AVS_GOVERNANCE, address(_sd.avsGovernance));
        _grantRole(RolesLibrary.AVS_GOVERNANCE, _newAvsGovernance);
        _sd.avsGovernance = IAvsGovernance(_newAvsGovernance);
        emit SetAvsGovernance(_newAvsGovernance);
    }

    // -------------------- Avs Governance Interface -------------------- //

    function sendMessage(bytes memory _message) external onlyRole(RolesLibrary.AVS_GOVERNANCE) {
        (bytes memory _dataMessage, uint32 _remoteId) = abi.decode(_message, (bytes, uint32));
        bytes4 _sig;
        assembly {
            _sig := mload(add(_dataMessage, 32))
        }
        if (_sig == MessagesLibrary.REGISTER_SIG || _sig == MessagesLibrary.UNREGISTER_SIG) {
            _lzSendMessageToAllEids(_dataMessage, _getL1MessageHandlerStorage().lzEids);
        } else {
            uint32[] memory _lzEids = new uint32[](1);
            _lzEids[0] = _remoteId;
            _lzSendMessageToAllEids(_dataMessage, _lzEids);
        }
    }

    // -------------------- L1AvsFactory Interface -------------------- //
    function setAvsGovernance(address _avsGovernance) external onlyRole(RolesLibrary.AVS_FACTORY_ROLE) {
        _getL1MessageHandlerStorage().avsGovernance = IAvsGovernance(_avsGovernance);
        _grantRole(RolesLibrary.AVS_GOVERNANCE, _avsGovernance);
        emit SetAvsGovernance(_avsGovernance);
    }

    function setNewSupportedL2(uint32 _lzEid) external onlyRole(RolesLibrary.AVS_FACTORY_ROLE) {
        L1MessageHandlerStorageData storage _sd = _getL1MessageHandlerStorage();
        for (uint256 i = 0; i < _sd.lzEids.length; i++) {
            if (_sd.lzEids[i] == _lzEid) {
                revert L2AlreadySupported(_lzEid);
            }
        }
        _sd.lzEids.push(_lzEid);
        emit NewSupportedL2(_lzEid);
    }

    /**
     * @dev Internal function to implement lzReceive logic without needing to copy the basic parameter validation.
     */
    function _lzReceive(
        Origin calldata _origin,
        bytes32, /* _guid */
        bytes calldata _message,
        address, /* _executor */
        bytes calldata /* _extraData */
    ) internal virtual override {
        (bytes4 _sig, bytes memory _body) = MessagesLibrary.PayloadToSig(_message);
        if (_sig == MessagesLibrary.OPERATOR_EJECTION_SIG) {
            _handleOperatorEjectionRequestMessage(_body);
        } else if (_sig == MessagesLibrary.BATCH_PAYMENT_SIG) {
            _handleBatchPaymentRequestMessage(_body, _origin.srcEid);
        } else if (_sig == MessagesLibrary.EIGEN_REWARDS_SIG) {
            _handleEigenRewardsRequestMessage(_body, _origin.srcEid);
        } else {
            revert("L1MessageHandler: Unknown message signature");
        }
    }

    function _handleOperatorEjectionRequestMessage(bytes memory _message) internal {
        address _operator = MessagesLibrary.ParseOperatorEjectionMessage(_message);
        emit OperatorEjectionRequested(_operator);
        _getL1MessageHandlerStorage().avsGovernance.ejectOperatorFromNetwork(_operator);
    }

    function _handleBatchPaymentRequestMessage(bytes memory _message, uint32 _remoteId) internal {
        (bytes memory _operatorsBytes, uint256 _lastPayedTask) =
            MessagesLibrary.ParseBatchPaymentRequestMessage(_message);
        IAvsGovernanceExtension.PaymentRequestMessage[] memory _operators =
            abi.decode(_operatorsBytes, (IAvsGovernanceExtension.PaymentRequestMessage[]));
        emit PaymentsRequested(_operators, _lastPayedTask);
        (bool _success,) = address(_getL1MessageHandlerStorage().avsGovernance).call(
            abi.encodeCall(IAvsGovernanceExtension.withdrawBatchRewards, (_operators, _lastPayedTask, _remoteId))
        );
        require(_success, "L1MessageHandler: BatchPaymentRequestMessage failed");
    }

    function _handleEigenRewardsRequestMessage(bytes memory _message, uint32 _remoteId) internal {
        (bytes memory _operatorsBytes, uint256 _lastPayedTask, bytes memory _data) =
            MessagesLibrary.ParseEigenRewardsRequestMessage(_message);
        IRewardsCoordinator.OperatorReward[] memory _operators =
            abi.decode(_operatorsBytes, (IRewardsCoordinator.OperatorReward[]));
        emit EigenPaymentsRequested(_operators, _lastPayedTask);
        _getL1MessageHandlerStorage().avsGovernance.createOperatorDirectedAVSRewardsSubmission(
            _operators, _lastPayedTask, _data, _remoteId
        );
    }

    function _getL1MessageHandlerStorage() internal pure returns (L1MessageHandlerStorageData storage sd) {
        return L1MessageHandlerStorage.load();
    }
}
