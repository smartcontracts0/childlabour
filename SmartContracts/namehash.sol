// SPDX-License-Identifier: MIT


pragma solidity ^0.8.0;

contract NameHasher {
    // Function to hash and store a name
    function hashAndStoreName(string memory name) public pure returns (bytes32) {
        // Convert the string to bytes
        bytes memory nameBytes = bytes(name);

        // Calculate the hash using SHA-256
        bytes32 nameHash = sha256(nameBytes);

        // Store the hash value on the blockchain
        // Typically, you would use a state variable or an event to store the hash.
        // For demonstration purposes, we'll just return it here.
        return nameHash;
    }
}