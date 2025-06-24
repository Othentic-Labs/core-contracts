// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

interface IStateReceiver {
    function onStateReceive(address sender, bytes calldata data) external;
}
