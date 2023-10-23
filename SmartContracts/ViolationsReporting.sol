// SPDX-License-Identifier: MIT

// File: @openzeppelin/contracts/security/ReentrancyGuard.sol


// OpenZeppelin Contracts (last updated v4.9.0) (security/ReentrancyGuard.sol)

pragma solidity ^0.8.0;

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuard {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        // On the first call to nonReentrant, _status will be _NOT_ENTERED
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");

        // Any calls to nonReentrant after this point will fail
        _status = _ENTERED;
    }

    function _nonReentrantAfter() private {
        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Returns true if the reentrancy guard is currently set to "entered", which indicates there is a
     * `nonReentrant` function in the call stack.
     */
    function _reentrancyGuardEntered() internal view returns (bool) {
        return _status == _ENTERED;
    }
}

// File: ViolationsReporting.sol




library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

pragma solidity ^0.8.16;

    //**** Interfaces ****//

    interface IRegistration{
        enum EntityType{Unregistered, RegulatoryAuthority, InspectionAgent, ReportingOracle, VerifyingOracle}
        function getEntity(address) external returns(EntityType, bool);
    }

    interface IVerifier{
        struct Proof {
            Pairing.G1Point a;
            Pairing.G2Point b;
            Pairing.G1Point c;
        }
        function verifyTx(Proof memory proof) external view returns (bool r);
    }


contract ViolationsReporting is ReentrancyGuard{

    //**** State Variable ****//
    IRegistration public Registration;
    IVerifier public Verifier;
    uint256 public reportCount;


    struct ViolationReport{
        address reportingOracle;
        uint256 timestamp;
        int256 latitude; // Store latitude in scaled integer format (e.g., multiplied by 1e6)
        int256 longitude; // Store longitude in scaled integer format (e.g., multiplied by 1e6)
        bytes32 evidence;
        bool isValid; //True if the violation report is considered valid, and it can be revoked by the RA
    }


    //Report ID => Report Details
    mapping(uint256 => ViolationReport) public violationReports;

    //DataAnalyst EA ==> bool
    mapping(address => bool) public accessWhitelist;


    //**** Constructor ****//
    constructor(address _registration, address _verifier){
        Registration = IRegistration(_registration);
        Verifier = IVerifier(_verifier);
        reportCount = 0;
    }

    //**** Modifiers ****//
    modifier onlyRegulatoryAuthority{
        (IRegistration.EntityType entitytype, bool isRegistered) = Registration.getEntity(msg.sender);
        require(entitytype == IRegistration.EntityType.RegulatoryAuthority && isRegistered, "Only the regulatory authority can run this function");
        _;
    }

    modifier onlyReportingOracle{
        (IRegistration.EntityType entitytype, bool isRegistered) = Registration.getEntity(msg.sender);
        require(entitytype == IRegistration.EntityType.ReportingOracle && isRegistered, "Only the Reporting Oracle can run this function");
        _;
    }

    modifier onlyInspectionAgent{
        (IRegistration.EntityType entitytype, bool isRegistered) = Registration.getEntity(msg.sender);
        require(entitytype == IRegistration.EntityType.InspectionAgent && isRegistered, "Only the Inspection Agent can run this function");
        _;
    }

    modifier onlyVerifyingOracle{
        (IRegistration.EntityType entitytype, bool isRegistered) = Registration.getEntity(msg.sender);
        require(entitytype == IRegistration.EntityType.VerifyingOracle && isRegistered, "Only the Verification Oracle can run this function");
        _;
    }
    //**** Events ****//
    event NewViolationReport(uint256 indexed reportCount,address reporter, int256 latitude, int256 longitude, uint256 date, bytes32 reportDetails);
    event ViolationReportVerification(uint256 indexed reportCount, address inspector, bool isVerified, uint256 verificationDate);
    event Whitelisted(address user, uint256 Date);
    event AccessRevoked(address regulatoryAuthority, address entity, uint256 date);
    event VerifierUpdated(address regulatoryAuthority, address verifierSC, uint256 date);
    event ReportValidityRevoked(address regulatoryAuthority, uint256 reportiD, uint256 date);

   
    //**** Functions ****//

    //The resource-contrained CCTV camera sends footage to cloud services via oracles for inspection
    //Any detected violation is recorded on the blockchain
    function recordViolation(string memory _evidencehash, int256 _latitude, int256 _longitude) public onlyReportingOracle nonReentrant{ 
        reportCount++;
        violationReports[reportCount] = ViolationReport(msg.sender, block.timestamp, _latitude, _longitude, bytes32(bytes(_evidencehash)), true);

        emit NewViolationReport(reportCount, msg.sender, _latitude,  _longitude, block.timestamp, bytes32(bytes(_evidencehash)));
    }


    //They assess the credibility of the report and determine whether further investigation is warranted.
    function getViolationReport(uint256 _violationReportId) public onlyInspectionAgent returns(address reporter, uint256 date, bytes32 reportDetails){
        require(_violationReportId >= 1 && _violationReportId <= reportCount, "Invalid Report ID");
        ViolationReport memory report = violationReports[_violationReportId];
        return(report.reportingOracle, report.timestamp, report.evidence);
    }

    function revokeReportValidity(uint256 _violationReportId) public onlyRegulatoryAuthority {
        ViolationReport memory report = violationReports[_violationReportId];
        require(_violationReportId >= 1 && _violationReportId <= reportCount, "Invalid Report ID");
        
        report.isValid = false;
        
        emit ReportValidityRevoked(msg.sender, _violationReportId, block.timestamp);
    }


    //It is assumed that inspectors data analysts with the proof are able to access all reports via the DPRE
    //The accessWhitelist mapping will be used by the DPRE to verify that the caller is eligible for reencryption
    function grantAccess(address _user) public onlyVerifyingOracle {
            accessWhitelist[_user] = true;
            emit Whitelisted(_user, block.timestamp);

    }

    //This decision can be made based on voting or by an arbitrator
    function revokeAccess( address _user) public onlyRegulatoryAuthority {
        accessWhitelist[_user] = false;
        emit AccessRevoked(msg.sender, _user, block.timestamp);
    }

    //This function is used when the proof is changed/updated for security purposes
    function updateVerifier(address _verifier) public onlyRegulatoryAuthority{
        Verifier = IVerifier(_verifier);
        emit VerifierUpdated(msg.sender, _verifier, block.timestamp);
    }

}

