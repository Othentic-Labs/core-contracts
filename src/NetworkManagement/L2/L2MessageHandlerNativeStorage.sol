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

import "@othentic/NetworkManagement/L2/interfaces/IAttestationCenter.sol";

struct L2MessageHandlerNativeStorageData {
    IAttestationCenter attestationCenter;
}

library L2MessageHandlerNativeStorage {
    uint256 private constant STORAGE_POSITION = uint256(keccak256("storage.l2.message.handler.native")) - 1;

    function load() internal pure returns (L2MessageHandlerNativeStorageData storage sd) {
        uint256 position = STORAGE_POSITION;
        assembly {
            sd.slot := position
        }
    }
}
