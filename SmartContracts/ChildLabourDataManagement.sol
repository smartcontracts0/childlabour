// SPDX-License-Identifier: MIT

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
        enum EntityType{RegulatoryAuthority, whistleBlowers, InspectionAgent, DataAnalyst, Guardian}
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


contract ChildLabourDataManagement{

    //**** State Variable ****//
    IRegistration public Registration;
    IVerifier public Verifier;
    uint256 public reportCount;
    uint256 public childCount;

    enum ChildStatus{Spotted, GuardianAssigned, InRemediation, TakenCareOf}


    struct ViolationReport{
        address reporter;
        uint256 timestamp;
        uint256 spottedChildrenNumber;
        bytes32 ipfsHash;
        bool isInspected;
        bool isVerified;
    }

    struct ChildData{
        uint256 childId;
        bytes32 hashedName; // Hashed child's name for privacy
        uint256 age;
        bytes1 gender;
        uint256 violationReportId;
        ChildStatus status;
    }

    struct ChildRemediation{
        address guardian;
        uint256 childId;
        uint256 remediationStart;
        uint256 remediationCompletion;
        uint256 lastUpdated;
        bytes32 updateReport;
        ChildStatus status;
    }

    //Report ID => Report Details
    mapping(uint256 => ViolationReport) public violationReports;

    //Child ID => Report Id
    mapping(uint256 => uint256) public child2ReportMapping; //Maps each spotted child to their corresponding report
    //Report ID => (Child number => Child details)
    mapping(uint256 => mapping(uint256 => ChildData)) public childData;

    // report ID => childcount
    mapping(uint256 => uint256) public reportChildrenCount;

    //(Child Number => Child Remediation Details)
    mapping(uint256 => ChildRemediation) public childRemediationData;

    //Child Id => GuardianAddress
    //mapping(uint256 => address) public childGuardian;

    //DataAnalyst EA ==> bool
    mapping(address => bool) public accessWhitelist;

    //Report ID => (Proof => bool)
    mapping(uint256 => IVerifier.Proof) public reportProof;

    //**** Constructor ****//
    constructor(address _registration, address _verifier){
        Registration = IRegistration(_registration);
        Verifier = IVerifier(_verifier);
        reportCount = 0;
        childCount = 0;
    }

    //**** Modifiers ****//
    modifier onlyRegulatoryAuthority{
        (IRegistration.EntityType entitytype, bool isRegistered) = Registration.getEntity(msg.sender);
        require(entitytype == IRegistration.EntityType.RegulatoryAuthority && isRegistered, "Only the regulatory authority can run this function");
        _;
    }

    modifier onlywhistleBlowers{
        (IRegistration.EntityType entitytype, bool isRegistered) = Registration.getEntity(msg.sender);
        require(entitytype == IRegistration.EntityType.whistleBlowers && isRegistered, "Only the Liaison Officer can run this function");
        _;
    }

    modifier onlyInspectionAgent{
        (IRegistration.EntityType entitytype, bool isRegistered) = Registration.getEntity(msg.sender);
        require(entitytype == IRegistration.EntityType.InspectionAgent && isRegistered, "Only the Inspection Agent can run this function");
        _;
    }

    modifier onlyDataAnalyst{
        (IRegistration.EntityType entitytype, bool isRegistered) = Registration.getEntity(msg.sender);
        require(entitytype == IRegistration.EntityType.DataAnalyst && isRegistered, "Only the Data Analyst can run this function");
        _;
    }

    modifier onlyGuardian(uint256 _childId){
        (IRegistration.EntityType entitytype, bool isRegistered) = Registration.getEntity(msg.sender);
        require(entitytype == IRegistration.EntityType.Guardian && isRegistered, "Only the Child Guardian can run this function");
        require(childRemediationData[_childId].guardian == msg.sender, "Only the assigned Guardian to this child can run this function");
        _;
    }
    //**** Events ****//
    event NewViolationReport(uint256 indexed reportCount,address reporter, uint256 date, bytes32 reportDetails);
    event ViolationReportVerification(uint256 indexed reportCount, address inspector, bool isVerified, uint256 verificationDate);
    event ChildDataStored(uint256 childId, bytes32 hashedName, uint256 age, bytes1 gender, uint256 reportId);
    event GuardianAssigned(uint256 childId, uint256 reportId, address guardian);
    event RemediationStarted(uint256 violationReportId, uint256 childId, uint256 remediationStartDate, uint256 remediationCompletionDate);
    event RemediationUpdate(uint256 violationReportId, uint256 childId, uint256 remediationUpdatedate, bytes32 reportUpdate);
    event RemediationCompleted(uint256 violationReportId, uint256 childId, uint256 remediationCompletionDate);
    event Whitelisted(address entity, uint256 Date);
    event AccessRevoked(address regulatoryAuthority, address entity, uint256 date);
    event VerifierUpdated(address regulatoryAuthority, address verifierSC, uint256 date);

   
   
    //**** Functions ****//

    //The whistleblower submits an initial report, providing details about the suspected child labor violation.
    function submitViolationReport(string memory _reportIPFSHash, uint256 _spottedChildrenNumber) public onlywhistleBlowers{
        
        reportCount++;
        violationReports[reportCount] = ViolationReport(msg.sender, block.timestamp, _spottedChildrenNumber, bytes32(bytes(_reportIPFSHash)), false, false);
        childCount += _spottedChildrenNumber;

        emit NewViolationReport(reportCount, msg.sender, block.timestamp, bytes32(bytes(_reportIPFSHash)));
    }

    //Child labor agents or investigators with expertise in child protection and labor laws review the initial report. 
    //They assess the credibility of the report and determine whether further investigation is warranted.
    function getViolationReport(uint256 _violationReportId) public onlyInspectionAgent returns(address reporter, uint256 date, bytes32 reportDetails){
        require(_violationReportId >= 1 && _violationReportId <= reportCount, "Invalid Report ID");
        ViolationReport memory report = violationReports[_violationReportId];
        return(report.reporter, report.timestamp, report.ipfsHash);
    }

    function verifyViolationReport(uint256 _violationReportId, bool _decision) public onlyInspectionAgent{
        require(_violationReportId >= 1 && _violationReportId <= reportCount, "Invalid Report ID");
        require(!violationReports[_violationReportId].isInspected, "This report has already been inspected");
        violationReports[_violationReportId].isInspected = true;
        violationReports[_violationReportId].isVerified = _decision;

        emit ViolationReportVerification(_violationReportId, msg.sender, _decision, block.timestamp);
    }

    //Note: The name should not be hashed on-chain because the decoded input will be publicaly exposed
    function storeChildData(bytes32 _hashedName, uint256 _age, bytes1 _gender, uint256 _violationReportId) public onlyInspectionAgent{
        require(_hashedName != bytes32(0), "Invalid hashed name");
        require(_age > 0 , "Invalid Age");
        require(bytes1(_gender) == "M" || bytes1(_gender) == "F", "Invalid Gender");
        require(_violationReportId >= 1 && _violationReportId <= reportCount, "Invalid Report ID");

        reportChildrenCount[_violationReportId] ++;
        childData[_violationReportId][reportChildrenCount[_violationReportId]] = ChildData(reportChildrenCount[_violationReportId], _hashedName, _age, _gender, _violationReportId, ChildStatus.Spotted);

        
        child2ReportMapping[reportChildrenCount[_violationReportId]] = _violationReportId;

        emit ChildDataStored(reportChildrenCount[_violationReportId], _hashedName, _age, _gender, _violationReportId);
    }

    function getChildData(uint256 _violationReportId, uint256 _childId) public onlyDataAnalyst returns(bytes32 hashedName, uint256 age, bytes1 gender, bytes32 reportipfshash){
        require(_violationReportId >= 1 && _violationReportId <= reportCount, "Invalid Report ID");
        require(_childId >= 1 && _childId <= reportChildrenCount[_violationReportId], "Invalid Child ID");
        ChildData memory data = childData[_violationReportId][_childId];
        ViolationReport memory report = violationReports[_violationReportId];


        return(data.hashedName, data.age, data.gender, report.ipfsHash);
    }

    function assignGuardian(uint256 _violationReportId, uint256 _childId, address _guardian) public onlyRegulatoryAuthority{
        ChildData memory data = childData[_violationReportId][_childId];
        require(data.status == ChildStatus.Spotted, "This child Id does not exist or has already been assigned a guardian");
        require(_violationReportId >= 1 && _violationReportId <= reportCount, "Invalid Report ID");
        require(_childId >= 1 && _childId <= reportChildrenCount[_violationReportId], "Invalid Child ID");


        childRemediationData[_childId].guardian = _guardian;
        childRemediationData[_childId].childId = _childId;
        childRemediationData[_childId].status = ChildStatus.GuardianAssigned;

        emit GuardianAssigned(_childId, _violationReportId, _guardian);

    }

    //TODO: change seconds back to days once testing is done
    function startRemediation(uint256 _violationReportId, uint256 _childId, uint256 _daysToRemediate) public onlyGuardian(_childId) {
        ChildRemediation memory remediationdata = childRemediationData[_childId];
        require(_violationReportId >= 1 && _violationReportId <= reportCount, "Invalid Report ID");
        require(_childId >= 1 && _childId <= reportChildrenCount[_violationReportId], "Invalid Child ID");
        require(remediationdata.status == ChildStatus.GuardianAssigned, "This child is not ready for remediation");

        childRemediationData[_childId].status = ChildStatus.InRemediation;
        childRemediationData[_childId].remediationStart = block.timestamp;
        childRemediationData[_childId].remediationCompletion = block.timestamp + _daysToRemediate * 1 seconds;
        childRemediationData[_childId].lastUpdated = block.timestamp;

        emit RemediationStarted(_violationReportId, _childId, block.timestamp, (block.timestamp + _daysToRemediate * 1 seconds));
    }

    function remediationUpdate(uint256 _violationReportId, uint256 _childId, string memory _updateReport) public onlyGuardian(_childId){
        ChildRemediation memory remediationdata = childRemediationData[_childId];
        require(_violationReportId >= 1 && _violationReportId <= reportCount, "Invalid Report ID");
        require(_childId >= 1 && _childId <= reportChildrenCount[_violationReportId], "Invalid Child ID");
        require(remediationdata.status == ChildStatus.InRemediation, "This child is not currently in remediation");

        childRemediationData[_childId].updateReport = bytes32(bytes(_updateReport));
        childRemediationData[_childId].lastUpdated = block.timestamp;
        emit RemediationUpdate(_violationReportId, _childId, block.timestamp, bytes32(bytes(_updateReport)));

    }

    function completeRemediation(uint256 _violationReportId, uint256 _childId) public onlyGuardian(_childId){
        ChildRemediation memory remediationdata = childRemediationData[_childId];
        require(_childId >= 1 && _childId <= reportChildrenCount[_violationReportId], "Invalid Child ID");
        require(remediationdata.status == ChildStatus.InRemediation, "This child is not currently in remediation");
        require(block.timestamp >= remediationdata.remediationCompletion, "The time window for remediation is still open");

        childRemediationData[_childId].status = ChildStatus.TakenCareOf;
        childRemediationData[_childId].lastUpdated = block.timestamp;

        emit RemediationCompleted(_violationReportId, _childId, block.timestamp);
    }

    function getChildStatus(uint256 _violationReportId, uint256 _childId) public onlyRegulatoryAuthority returns(ChildStatus, uint256, uint256, uint256){
        ChildRemediation memory remediationdata = childRemediationData[_childId];
        require(_violationReportId >= 1 && _violationReportId <= reportCount, "Invalid Report ID");
        require(_childId >= 1 && _childId <= reportChildrenCount[_violationReportId], "Invalid Child ID");
        return(remediationdata.status, remediationdata.lastUpdated, remediationdata.remediationStart, remediationdata.remediationCompletion);
    }


    //It is assumed that inspectors data analysts with the proof are able to access all reports via the DPRE
    //The accessWhitelist mapping will be used by the DPRE to verify that the caller is eligible for reencryption
    function grantAccess(IVerifier.Proof memory proof) public returns(bool) {

        bool r = Verifier.verifyTx(proof);

        if (r){
            accessWhitelist[msg.sender] = true;
            emit Whitelisted(msg.sender, block.timestamp);
            return true;
        } else {
            return false;
        }
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