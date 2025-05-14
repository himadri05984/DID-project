import pytest
import os
from app import app, db
from models import User, DID, Credential, Revocation
from blockchain import BlockchainIntegration
from wallet import DIDWallet
from werkzeug.security import generate_password_hash
from datetime import datetime

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

def test_blockchain_initialization():
    """Test blockchain integration initialization"""
    blockchain = BlockchainIntegration()
    
    # Since we don't have real Ethereum node access in tests,
    # the blockchain connection should be simulated
    assert hasattr(blockchain, 'connected')
    
    # Default test environment should not have real connections
    assert blockchain.connected is False

def test_anchor_did_on_chain(client):
    """Test anchoring a DID on the blockchain"""
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        
        # Create a DID for the user
        did_document = DIDWallet.create_did(user.id, "ethr")
        did_id = did_document["id"]
        
        # Anchor the DID on the blockchain
        blockchain = BlockchainIntegration()
        tx_hash = blockchain.anchor_did_on_chain(did_id, user.id)
        
        # Check that a transaction hash was generated (simulated in test)
        assert tx_hash is not None
        assert tx_hash.startswith("0x")
        
        # Verify the DID was updated with the transaction hash
        did = DID.query.filter_by(did_id=did_id).first()
        assert did.blockchain_tx_hash == tx_hash

def test_verify_did_on_chain(client):
    """Test verifying a DID on the blockchain"""
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        
        # Create a DID for the user
        did_document = DIDWallet.create_did(user.id, "ethr")
        did_id = did_document["id"]
        
        # Anchor the DID on the blockchain
        blockchain = BlockchainIntegration()
        tx_hash = blockchain.anchor_did_on_chain(did_id, user.id)
        
        # Verify the DID on the blockchain
        verification_result = blockchain.verify_did_on_chain(did_id)
        
        # Check verification result
        assert verification_result["verified"] == True
        assert verification_result["tx_hash"] == tx_hash
        assert "timestamp" in verification_result

def test_verify_unanchored_did(client):
    """Test verifying an unanchored DID"""
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        
        # Create a DID for the user but don't anchor it
        did_document = DIDWallet.create_did(user.id, "ethr")
        did_id = did_document["id"]
        
        # Verify the DID on the blockchain
        blockchain = BlockchainIntegration()
        verification_result = blockchain.verify_did_on_chain(did_id)
        
        # Check verification result
        assert verification_result["verified"] == False
        assert "reason" in verification_result

def test_anchor_credential(client):
    """Test anchoring a credential on the blockchain"""
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        
        # Create a DID for the user
        did_document = DIDWallet.create_did(user.id, "ethr")
        issuer_did = did_document["id"]
        
        # Create another DID as the holder
        holder_did_document = DIDWallet.create_did(user.id, "ethr")
        holder_did = holder_did_document["id"]
        
        # Create a credential
        credential = Credential(
            credential_id="vc:test:123",
            issuer_did=issuer_did,
            holder_did=holder_did,
            user_id=user.id,
            type="TestCredential",
            issuance_date=datetime.utcnow(),
            credential_data="{}"
        )
        db.session.add(credential)
        db.session.commit()
        
        # Anchor the credential
        blockchain = BlockchainIntegration()
        tx_hash = blockchain.anchor_credential(credential.credential_id, user.id)
        
        # Check that a transaction hash was generated
        assert tx_hash is not None
        assert tx_hash.startswith("0x")
        
        # Verify the credential was updated with the blockchain proof
        updated_credential = Credential.query.filter_by(credential_id=credential.credential_id).first()
        assert updated_credential.blockchain_proof == tx_hash

def test_revocation_registration(client):
    """Test registering a credential revocation"""
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        
        # Create a DID for the user
        did_document = DIDWallet.create_did(user.id, "ethr")
        issuer_did = did_document["id"]
        
        # Create a credential
        credential = Credential(
            credential_id="vc:test:456",
            issuer_did=issuer_did,
            holder_did="did:example:holder",
            user_id=user.id,
            type="TestCredential",
            issuance_date=datetime.utcnow(),
            credential_data="{}"
        )
        db.session.add(credential)
        db.session.commit()
        
        # Register revocation
        blockchain = BlockchainIntegration()
        reason = "Test revocation reason"
        tx_hash = blockchain.register_revocation(credential.credential_id, issuer_did, reason)
        
        # Check that a transaction hash was generated
        assert tx_hash is not None
        assert tx_hash.startswith("0x")
        
        # Verify the credential was marked as revoked
        updated_credential = Credential.query.filter_by(credential_id=credential.credential_id).first()
        assert updated_credential.revoked == True
        assert updated_credential.revocation_date is not None
        
        # Verify a revocation record was created
        revocation = Revocation.query.filter_by(credential_id=credential.credential_id).first()
        assert revocation is not None
        assert revocation.issuer_did == issuer_did
        assert revocation.reason == reason
        assert revocation.blockchain_tx_hash == tx_hash

def test_check_revocation_status(client):
    """Test checking a credential's revocation status"""
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        
        # Create a DID for the user
        did_document = DIDWallet.create_did(user.id, "ethr")
        issuer_did = did_document["id"]
        
        # Create a credential
        credential = Credential(
            credential_id="vc:test:789",
            issuer_did=issuer_did,
            holder_did="did:example:holder",
            user_id=user.id,
            type="TestCredential",
            issuance_date=datetime.utcnow(),
            credential_data="{}"
        )
        db.session.add(credential)
        db.session.commit()
        
        # Check revocation status before revocation
        blockchain = BlockchainIntegration()
        status_before = blockchain.check_revocation_status(credential.credential_id)
        
        # Verify status shows not revoked
        assert status_before["revoked"] == False
        
        # Register revocation
        tx_hash = blockchain.register_revocation(credential.credential_id, issuer_did, "Testing revocation")
        
        # Check revocation status after revocation
        status_after = blockchain.check_revocation_status(credential.credential_id)
        
        # Verify status shows revoked
        assert status_after["revoked"] == True
        assert "revocation_date" in status_after
        assert "reason" in status_after
        assert status_after["reason"] == "Testing revocation"
        assert status_after["tx_hash"] == tx_hash

def test_nonexistent_credential_revocation_status():
    """Test checking revocation status for a nonexistent credential"""
    blockchain = BlockchainIntegration()
    status = blockchain.check_revocation_status("vc:nonexistent:123")
    
    # Should return an error
    assert "error" in status
    assert status["error"] == "Credential not found"
