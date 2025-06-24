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

import {MessageHandlerNative} from "@othentic/NetworkManagement/Common/MessageHandlerNative.sol";
import {IAttestationCenter} from "@othentic/NetworkManagement/L2/interfaces/IAttestationCenter.sol";
import {IL2MessageHandler} from "@othentic/NetworkManagement/L2/interfaces/IL2MessageHandler.sol";
import {L1MessageHandlerStorage} from "@othentic/NetworkManagement/L1/L1MessageHandlerStorage.sol";
import {MessagesLibrary} from "@othentic/NetworkManagement/Common/MessagesLibrary.sol";
import {RolesLibrary} from "@othentic/NetworkManagement/Common/RolesLibrary.sol";
import {IStateReceiver} from "@othentic/NetworkManagement/Common/interfaces/NativeBridge/IStateReceiver.sol";
import {
    L2MessageHandlerNativeStorage,
    L2MessageHandlerNativeStorageData
} from "@othentic/NetworkManagement/L2/L2MessageHandlerNativeStorage.sol";

contract L2MessageHandlerNative is IStateReceiver, IL2MessageHandler, MessageHandlerNative {
    function initialize(
        address _avsGovernanceMultisigOwner,
        address _operationsMultisig,
        address _communityMultisig,
        address _stateSenderAddress,
        address _localStateReceiverAddress
    ) public initializer {
        _initialize(
            _avsGovernanceMultisigOwner,
            _operationsMultisig,
            _communityMultisig,
            _stateSenderAddress,
            _localStateReceiverAddress
        );
    }

    function setAttestationCenter(address _attestationCenterAddress) external onlyRole(RolesLibrary.AVS_FACTORY_ROLE) {
        _getL2MessageHandlerNativeStorage().attestationCenter = IAttestationCenter(_attestationCenterAddress);
        _grantRole(RolesLibrary.ATTESTATION_CENTER, _attestationCenterAddress);
        emit SetAttestationCenter(_attestationCenterAddress);
    }

    function getAttestationCenter() external view returns (address) {
        return address(_getL2MessageHandlerNativeStorage().attestationCenter);
    }

    function transferAttestationCenter(address _newAttestationCenterAddress)
        external
        onlyRole(RolesLibrary.OPERATIONS_MULTISIG)
    {
        L2MessageHandlerNativeStorageData storage _sd = _getL2MessageHandlerNativeStorage();
        _revokeRole(RolesLibrary.ATTESTATION_CENTER, address(_sd.attestationCenter));
        _grantRole(RolesLibrary.ATTESTATION_CENTER, _newAttestationCenterAddress);
        _sd.attestationCenter = IAttestationCenter(_newAttestationCenterAddress);
        emit SetAttestationCenter(_newAttestationCenterAddress);
    }

    function onStateReceive(address, /* sender */ bytes calldata data)
        external
        override
        onlyRole(RolesLibrary.STATE_RECEIVER)
    {
        (bytes4 _sig, bytes memory _body) = MessagesLibrary.PayloadToSig(data);
        if (_sig == MessagesLibrary.REGISTER_SIG) {
            _handleRegisterOperatorMessage(_body);
        } else if (_sig == MessagesLibrary.BATCH_CLEAR_SIG) {
            _handleBatchClearMessage(_body);
        } else if (_sig == MessagesLibrary.UNREGISTER_SIG) {
            _handleUnregisterOperatorMessage(_body);
        } else {
            revert("L2MessageHandlerNative: Unknown message signature");
        }
    }

    function _handleRegisterOperatorMessage(bytes memory _message) internal {
        (address _operator, uint256 _votingPower, uint256[4] memory _blsKey, address _rewardsReceiver) =
            MessagesLibrary.ParseRegisterToAvsMessage(_message);
        _getL2MessageHandlerNativeStorage().attestationCenter.registerToNetwork(
            _operator, _votingPower, _blsKey, _rewardsReceiver
        );
    }

    function _handleBatchClearMessage(bytes memory _message) internal {
        (bytes memory _operatorsBytes, uint256 _lastPaidTasksNumber) = MessagesLibrary.ParseBatchClearMessage(_message);
        IAttestationCenter.PaymentRequestMessage[] memory _operators =
            abi.decode(_operatorsBytes, (IAttestationCenter.PaymentRequestMessage[]));
        _getL2MessageHandlerNativeStorage().attestationCenter.clearBatchPayment(_operators, _lastPaidTasksNumber);
    }

    function _handleUnregisterOperatorMessage(bytes memory _message) internal {
        address _operator = MessagesLibrary.ParseUnregisterOperatorMessage(_message);
        _getL2MessageHandlerNativeStorage().attestationCenter.unRegisterOperatorFromNetwork(_operator);
    }

    function sendMessage(bytes memory message) external onlyRole(RolesLibrary.ATTESTATION_CENTER) {
        _sendMessage(message);
    }

    function _getL2MessageHandlerNativeStorage() internal pure returns (L2MessageHandlerNativeStorageData storage sd) {
        return L2MessageHandlerNativeStorage.load();
    }
}
