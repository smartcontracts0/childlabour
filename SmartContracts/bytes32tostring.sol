// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Bytes32ToStringExample {
    function bytes32ToString(bytes32 data) public pure returns (string memory) {
        bytes memory bytesArray = new bytes(32);
        for (uint256 i = 0; i < 32; i++) {
            bytesArray[i] = data[i];
        }
        return string(bytesArray);
    }

        function stringToBytes(string memory data) public pure returns (bytes memory) {
        return bytes(data);
    }
}