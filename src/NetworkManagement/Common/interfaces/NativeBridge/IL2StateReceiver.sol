// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

interface IL2StateReceiver {
    function onL2StateReceive(address sender, bytes calldata data) external;
}
