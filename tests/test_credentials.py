import pytest
import json
from datetime import datetime, timedelta
from app import app, db
from models import User, DID, Credential
from wallet import DIDWallet
from credentials import CredentialManager
from blockchain import BlockchainIntegration
from werkzeug.security import generate_password_hash

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            # Create a test user
            test_user = User(
                username='testuser',
                email='test@example.com',
                password_hash=generate_password_hash('password')
            )
            db.session.add(test_user)
            db.session.commit()
            yield client
            
            # Clean up
            db.session.remove()
            db.drop_all()

def test_issue_credential(client):
    """Test issuing a verifiable credential"""
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        
        # Create a DID for the issuer
        issuer_did_doc = DIDWallet.create_did(user.id, "ethr")
        issuer_did = issuer_did_doc["id"]
        
        # Create a DID for the holder
        holder_did_doc = DIDWallet.create_did(user.id, "ethr")
        holder_did = holder_did_doc["id"]
        
        # Define credential claims
        credential_type = "UniversityDegree"
        claims = {
            "degreeName": "Bachelor of Science",
            "degreeType": "Bachelor's",
            "university": "Example University",
            "graduationDate": "2023-05-15",
            "fieldOfStudy": "Computer Science"
        }
        
        # Issue the credential
        credential = CredentialManager.issue_credential(
            issuer_did=issuer_did,
            holder_did=holder_did,
            credential_type=credential_type,
            claims=claims,
            user_id=user.id
        )
        
        # Check credential structure
        assert credential is not None
        assert "@context" in credential
        assert "id" in credential
        assert "type" in credential
        assert "issuer" in credential
        assert "issuanceDate" in credential
        assert "credentialSubject" in credential
        assert "proof" in credential
        
        # Check credential content
        assert credential["issuer"] == issuer_did
        assert credential["credentialSubject"]["id"] == holder_did
        assert credential["type"][1] == credential_type
        
        # Check claims
        for key, value in claims.items():
            assert credential["credentialSubject"][key] == value
            
        # Check proof
        assert credential["proof"]["type"] == "RsaSignature2018"
        assert credential["proof"]["proofPurpose"] == "assertionMethod"
        assert "jws" in credential["proof"]
        
        # Verify the credential was stored in the database
        db_credential = Credential.query.filter_by(issuer_did=issuer_did, holder_did=holder_did).first()
        assert db_credential is not None
        assert db_credential.type == credential_type

def test_verify_credential(client):
    """Test verifying a credential"""
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        
        # Create DIDs for issuer and holder
        issuer_did_doc = DIDWallet.create_did(user.id, "ethr")
        issuer_did = issuer_did_doc["id"]
        holder_did_doc = DIDWallet.create_did(user.id, "ethr")
        holder_did = holder_did_doc["id"]
        
        # Issue a credential
        credential = CredentialManager.issue_credential(
            issuer_did=issuer_did,
            holder_did=holder_did,
            credential_type="EmploymentCredential",
            claims={
                "employer": "Example Corp",
                "jobTitle": "Software Engineer",
                "startDate": "2022-01-15",
                "department": "Engineering"
            },
            user_id=user.id
        )
        
        # Verify the credential
        verification_result = CredentialManager.verify_credential(credential)
        
        # Check verification result
        assert verification_result["verified"] == True
        assert verification_result["issuer"] == issuer_did
        assert verification_result["holder"] == holder_did
        
        # Test with tampered credential
        tampered_credential = credential.copy()
        tampered_credential["credentialSubject"]["jobTitle"] = "CEO"
        
        tampered_result = CredentialManager.verify_credential(tampered_credential)
        
        # Should fail verification
        assert tampered_result["verified"] == False
        assert "reason" in tampered_result

def test_credential_with_expiration(client):
    """Test credentials with expiration dates"""
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        
        # Create DIDs
        issuer_did_doc = DIDWallet.create_did(user.id, "ethr")
        issuer_did = issuer_did_doc["id"]
        holder_did_doc = DIDWallet.create_did(user.id, "ethr")
        holder_did = holder_did_doc["id"]
        
        # Issue a credential that expires tomorrow
        future_date = datetime.utcnow() + timedelta(days=1)
        valid_credential = CredentialManager.issue_credential(
            issuer_did=issuer_did,
            holder_did=holder_did,
            credential_type="MembershipCredential",
            claims={
                "organization": "Example Club",
                "membershipId": "12345",
                "membershipLevel": "Gold"
            },
            expiration_date=future_date,
            user_id=user.id
        )
        
        # Issue a credential that expired yesterday
        past_date = datetime.utcnow() - timedelta(days=1)
        expired_credential = CredentialManager.issue_credential(
            issuer_did=issuer_did,
            holder_did=holder_did,
            credential_type="MembershipCredential",
            claims={
                "organization": "Example Club",
                "membershipId": "67890",
                "membershipLevel": "Silver"
            },
            expiration_date=past_date,
            user_id=user.id
        )
        
        # Verify the valid credential
        valid_result = CredentialManager.verify_credential(valid_credential)
        assert valid_result["verified"] == True
        
        # Verify the expired credential
        expired_result = CredentialManager.verify_credential(expired_credential)
        assert expired_result["verified"] == False
        assert "expired" in expired_result["reason"].lower()

def test_revoke_credential(client):
    """Test revoking a credential"""
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        
        # Create DIDs
        issuer_did_doc = DIDWallet.create_did(user.id, "ethr")
        issuer_did = issuer_did_doc["id"]
        holder_did_doc = DIDWallet.create_did(user.id, "ethr")
        holder_did = holder_did_doc["id"]
        
        # Issue a credential
        credential = CredentialManager.issue_credential(
            issuer_did=issuer_did,
            holder_did=holder_did,
            credential_type="DriverLicense",
            claims={
                "licenseNumber": "DL12345",
                "issuingAuthority": "Example DMV",
                "vehicleCategories": "B"
            },
            user_id=user.id
        )
        
        # Verify before revocation
        before_revocation = CredentialManager.verify_credential(credential)
        assert before_revocation["verified"] == True
        
        # Revoke the credential
        revocation_result = CredentialManager.revoke_credential(
            credential_id=credential["id"],
            issuer_did=issuer_did,
            user_id=user.id,
            reason="License suspended"
        )
        
        assert revocation_result == True
        
        # Get the credential from the database
        db_credential = Credential.query.filter_by(credential_id=credential["id"]).first()
        assert db_credential.revoked == True
        assert db_credential.revocation_date is not None
        
        # Verify after revocation
        after_revocation = CredentialManager.verify_credential(credential)
        assert after_revocation["verified"] == False
        assert "revoked" in after_revocation["reason"].lower()

def test_create_presentation(client):
    """Test creating a verifiable presentation with selective disclosure"""
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        
        # Create DIDs
        issuer_did_doc = DIDWallet.create_did(user.id, "ethr")
        issuer_did = issuer_did_doc["id"]
        holder_did_doc = DIDWallet.create_did(user.id, "ethr")
        holder_did = holder_did_doc["id"]
        verifier_did = "did:example:verifier"
        
        # Issue credentials
        credential1 = CredentialManager.issue_credential(
            issuer_did=issuer_did,
            holder_did=holder_did,
            credential_type="UniversityDegree",
            claims={
                "degreeName": "Bachelor of Science",
                "degreeType": "Bachelor's",
                "university": "Example University",
                "graduationDate": "2023-05-15",
                "fieldOfStudy": "Computer Science",
                "gpa": "3.8"
            },
            user_id=user.id
        )
        
        credential2 = CredentialManager.issue_credential(
            issuer_did=issuer_did,
            holder_did=holder_did,
            credential_type="EmploymentCredential",
            claims={
                "employer": "Example Corp",
                "jobTitle": "Software Engineer",
                "startDate": "2022-01-15",
                "department": "Engineering",
                "salary": "100000"
            },
            user_id=user.id
        )
        
        # Create a presentation with selective disclosure
        disclosed_attributes = {
            credential1["id"]: ["degreeName", "university", "graduationDate"],
            credential2["id"]: ["employer", "jobTitle"]
        }
        
        presentation = CredentialManager.create_presentation(
            credential_ids=[credential1["id"], credential2["id"]],
            holder_did=holder_did,
            user_id=user.id,
            verifier_did=verifier_did,
            disclosed_attributes=disclosed_attributes
        )
        
        # Check presentation structure
        assert presentation is not None
        assert "@context" in presentation
        assert "id" in presentation
        assert "type" in presentation
        assert "holder" in presentation
        assert "verifier" in presentation
        assert "verifiableCredential" in presentation
        assert "proof" in presentation
        
        # Check selective disclosure
        for credential in presentation["verifiableCredential"]:
            if credential["id"] == credential1["id"]:
                subject = credential["credentialSubject"]
                # Should include these fields
                assert "degreeName" in subject
                assert "university" in subject
                assert "graduationDate" in subject
                # Should not include these fields
                assert "gpa" not in subject
                assert "fieldOfStudy" not in subject
                # Should include metadata about selective disclosure
                assert "_selective_disclosure" in credential
                
            if credential["id"] == credential2["id"]:
                subject = credential["credentialSubject"]
                # Should include these fields
                assert "employer" in subject
                assert "jobTitle" in subject
                # Should not include these fields
                assert "salary" not in subject
                assert "startDate" not in subject
                # Should include metadata about selective disclosure
                assert "_selective_disclosure" in credential

def test_verify_presentation(client):
    """Test verifying a presentation"""
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        
        # Create DIDs
        issuer_did_doc = DIDWallet.create_did(user.id, "ethr")
        issuer_did = issuer_did_doc["id"]
        holder_did_doc = DIDWallet.create_did(user.id, "ethr")
        holder_did = holder_did_doc["id"]
        verifier_did = "did:example:verifier"
        
        # Issue a credential
        credential = CredentialManager.issue_credential(
            issuer_did=issuer_did,
            holder_did=holder_did,
            credential_type="HealthCredential",
            claims={
                "healthProvider": "Example Hospital",
                "certificationType": "COVID-19 Vaccination",
                "issueDate": "2022-03-10"
            },
            user_id=user.id
        )
        
        # Create a presentation
        presentation = CredentialManager.create_presentation(
            credential_ids=[credential["id"]],
            holder_did=holder_did,
            user_id=user.id,
            verifier_did=verifier_did
        )
        
        # Verify the presentation
        verification_result = CredentialManager.verify_presentation(presentation)
        
        # Check verification result
        assert verification_result["verified"] == True
        assert verification_result["holder"] == holder_did
        assert verification_result["credentials_verified"] == 1
        assert verification_result["credentials_failed"] == 0
        assert len(verification_result["verified_credentials"]) == 1
        
        # Test with tampered presentation
        tampered_presentation = presentation.copy()
        tampered_presentation["holder"] = "did:example:imposter"
        
        tampered_result = CredentialManager.verify_presentation(tampered_presentation)
        
        # Should fail verification
        assert tampered_result["verified"] == False
