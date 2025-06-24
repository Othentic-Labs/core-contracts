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

import "@othentic/NetworkManagement/Common/interfaces/NativeBridge/IStateSender.sol";

struct MessageHandlerNativeStorageData {
    IStateSender stateSender;
    address remoteStateReceiverAddress;
    address localStateReceiverAddress;
}

library MessageHandlerNativeStorage {
    uint256 private constant STORAGE_POSITION = uint256(keccak256("storage.message.handler.native")) - 1;

    function load() internal pure returns (MessageHandlerNativeStorageData storage sd) {
        uint256 position = STORAGE_POSITION;
        assembly {
            sd.slot := position
        }
    }
}
