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

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IAvsTreasury} from "@othentic/NetworkManagement/Common/interfaces/IAvsTreasury.sol";

struct AvsTreasuryStorageData {
    address avsTreasuryOwner;
    IERC20 token;
    address otTreasury;
    uint256 protocolFee;
    uint256 balance;
    uint32 tokenReplacementModificationDelay;
    IAvsTreasury.TokenReplacementDetails tokenReplacementDetails;
}

library AvsTreasuryStorage {
    uint256 private constant STORAGE_POSITION = uint256(keccak256("storage.vault")) - 1;

    function load() internal pure returns (AvsTreasuryStorageData storage sd) {
        uint256 position = STORAGE_POSITION;
        assembly {
            sd.slot := position
        }
    }
}
