// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

interface IStateSender {
    function syncState(address receiver, bytes calldata data) external;
}
