// SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.25;

import {IAVSDirectory} from "@eigenlayer/contracts/interfaces/IAVSDirectory.sol";

// Eigen does not ship their AvsDirectory interface with this function
interface IAVSDirectoryFull is IAVSDirectory {
    function avsOperatorStatus(address avs, address operator) external view returns (OperatorAVSRegistrationStatus);
}
