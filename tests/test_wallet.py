import pytest
import json
from app import app, db
from models import User, DID
from wallet import DIDWallet
from werkzeug.security import generate_password_hash

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    
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

def test_generate_key_pair():
    """Test generating a key pair"""
    private_key, public_key = DIDWallet.generate_key_pair()
    
    assert private_key is not None
    assert public_key is not None
    assert "BEGIN PRIVATE KEY" in private_key
    assert "BEGIN PUBLIC KEY" in public_key

def test_create_did(client):
    """Test creating a new DID"""
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        
        # Create a DID for the user
        did_document = DIDWallet.create_did(user.id, "ethr")
        
        # Check that the DID was created correctly
        assert did_document is not None
        assert "@context" in did_document
        assert "id" in did_document
        assert did_document["id"].startswith("did:ethr:")
        
        # Check that the DID was stored in the database
        did = DID.query.filter_by(user_id=user.id).first()
        assert did is not None
        assert did.did_id == did_document["id"]
        assert did.method == "ethr"
        assert did.active == True

def test_get_did_document(client):
    """Test retrieving a DID document"""
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        
        # Create a DID for the user
        did_document = DIDWallet.create_did(user.id, "ethr")
        did_id = did_document["id"]
        
        # Get the DID document
        retrieved_document = DIDWallet.get_did_document(did_id)
        
        # Check that the document was retrieved correctly
        assert retrieved_document is not None
        assert retrieved_document["id"] == did_id
        assert "verificationMethod" in retrieved_document

def test_list_user_dids(client):
    """Test listing all DIDs for a user"""
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        
        # Create multiple DIDs for the user
        DIDWallet.create_did(user.id, "ethr")
        DIDWallet.create_did(user.id, "web")
        
        # List the user's DIDs
        did_list = DIDWallet.list_user_dids(user.id)
        
        # Check that all DIDs were retrieved
        assert len(did_list) == 2
        assert did_list[0]["id"].startswith("did:ethr:") or did_list[0]["id"].startswith("did:web:")
        assert did_list[1]["id"].startswith("did:ethr:") or did_list[1]["id"].startswith("did:web:")

def test_deactivate_did(client):
    """Test deactivating a DID"""
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        
        # Create a DID for the user
        did_document = DIDWallet.create_did(user.id, "ethr")
        did_id = did_document["id"]
        
        # Deactivate the DID
        result = DIDWallet.deactivate_did(did_id, user.id)
        
        # Check that the DID was deactivated
        assert result == True
        
        # Verify in the database
        did = DID.query.filter_by(did_id=did_id).first()
        assert did.active == False
        
        # Check that the DID document was updated
        updated_document = json.loads(did.document)
        assert "deactivated" in updated_document
        assert updated_document["deactivated"] == True

def test_sign_and_verify_data(client):
    """Test signing and verifying data with a DID"""
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        
        # Create a DID for the user
        did_document = DIDWallet.create_did(user.id, "ethr")
        did_id = did_document["id"]
        
        # Test data to sign
        test_data = {"test": "data", "number": 123}
        
        # Sign the data
        signature = DIDWallet.sign_data(did_id, user.id, test_data)
        
        # Verify the signature
        verification_result = DIDWallet.verify_signature(did_id, test_data, signature)
        
        # Check that the signature is valid
        assert verification_result == True
        
        # Test with tampered data
        tampered_data = {"test": "tampered", "number": 123}
        tampered_verification = DIDWallet.verify_signature(did_id, tampered_data, signature)
        
        # Check that the verification fails with tampered data
        assert tampered_verification == False

def test_nonexistent_did():
    """Test operations with a nonexistent DID"""
    nonexistent_did = "did:example:nonexistent"
    
    # Try to get a nonexistent DID document
    document = DIDWallet.get_did_document(nonexistent_did)
    assert document is None
    
    # Try to verify a signature with a nonexistent DID
    verification = DIDWallet.verify_signature(nonexistent_did, {"test": "data"}, "invalid-signature")
    assert verification == False
