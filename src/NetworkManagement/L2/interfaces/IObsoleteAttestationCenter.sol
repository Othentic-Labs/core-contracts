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

import {TaskDefinitionParams} from "../TaskDefinitionLibrary.sol";

interface IObsoleteAttestationCenter {
    event SetRestrictedAttester(uint16 indexed taskDefinitionId, uint256[] restrictedAttesterIds);
    event SetMaximumNumberOfAttesters(uint16 indexed taskDefinitionId, uint256 maximumNumberOfAttesters);

    error InvalidRestrictedAttesterIds();
    error InvalidMaximumNumberOfAttesters();
    error TaskDefinitionNotFound(uint16 taskDefinitionId);
    error AlreadyMigrated();

    // @backward-compatibility used in mainnet and older CLI versions
    function createNewTaskDefinition(string memory _name, TaskDefinitionParams calldata _taskDefinitionParams)
        external
        returns (uint16 _id);

    // @backward-compatibility used in mainnet and older CLI versions
    function getTaskDefinitionMaximumNumberOfOperators(uint16 _taskDefinitionId) external view returns (uint256);

    // @backward-compatibility used in mainnet and older CLI versions
    function getTaskDefinitionRestrictedOperators(uint16 _taskDefinitionId) external view returns (uint256[] memory);

    // @backward-compatibility used in mainnet and older CLI versions
    function setTaskDefinitionRestrictedOperators(uint16 _taskDefinitionId, uint256[] calldata _restrictedAttesterIds)
        external;

    // @backward-compatibility used in mainnet and older CLI versions
    function setTaskDefinitionMaximumNumberOfOperators(uint16 _taskDefinitionId, uint256 _maximumNumberOfAttesters)
        external;
}
