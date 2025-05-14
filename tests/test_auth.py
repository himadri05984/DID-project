import pytest
import os
import jwt
from datetime import datetime, timedelta
from app import app, db
from models import User, VerificationRequest
from auth import Auth
from wallet import DIDWallet
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import current_user

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            
            # Clean up
            db.session.remove()
            db.drop_all()

def test_user_registration(client):
    """Test user registration"""
    with app.app_context():
        # Register a new user
        user = Auth.register_user(
            username='testuser',
            email='test@example.com',
            password='password123'
        )
        
        # Check that the user was created correctly
        assert user is not None
        assert user.username == 'testuser'
        assert user.email == 'test@example.com'
        assert check_password_hash(user.password_hash, 'password123')
        
        # Try to register with the same username
        duplicate_user = Auth.register_user(
            username='testuser',
            email='different@example.com',
            password='password456'
        )
        
        # Should fail due to duplicate username
        assert duplicate_user is None
        
        # Try to register with the same email
        duplicate_email = Auth.register_user(
            username='different',
            email='test@example.com',
            password='password456'
        )
        
        # Should fail due to duplicate email
        assert duplicate_email is None

def test_user_login_logout(client):
    """Test user login and logout"""
    with app.app_context():
        # Register a user
        Auth.register_user('testuser', 'test@example.com', 'password123')
        
        # Test login with username
        with client.session_transaction():
            user1 = Auth.login('testuser', 'password123')
            assert user1 is not None
            assert user1.username == 'testuser'
        
        # Test login with email
        with client.session_transaction():
            user2 = Auth.login('test@example.com', 'password123')
            assert user2 is not None
            assert user2.email == 'test@example.com'
        
        # Test login with incorrect password
        with client.session_transaction():
            user3 = Auth.login('testuser', 'wrongpassword')
            assert user3 is None
        
        # Test login with nonexistent user
        with client.session_transaction():
            user4 = Auth.login('nonexistent', 'password123')
            assert user4 is None
        
        # Test logout
        with client.session_transaction():
            result = Auth.logout()
            assert result is True

def test_did_auth_challenge():
    """Test generating a DID authentication challenge"""
    did_id = "did:example:123456789abcdefghi"
    
    # Generate a challenge
    challenge_response = Auth.did_auth_challenge(did_id)
    
    # Check challenge structure
    assert "challenge" in challenge_response
    assert "token" in challenge_response
    
    challenge = challenge_response["challenge"]
    token = challenge_response["token"]
    
    # Check challenge content
    assert challenge["type"] == "DIDAuthChallenge"
    assert challenge["did"] == did_id
    assert "nonce" in challenge
    assert "created" in challenge
    assert "expires" in challenge
    
    # Verify token decodes to the challenge
    decoded = jwt.decode(token, Auth.JWT_SECRET, algorithms=["HS256"])
    assert decoded["did"] == did_id
    assert decoded["nonce"] == challenge["nonce"]

def test_verification_request(client):
    """Test creating and responding to verification requests"""
    with app.app_context():
        # Register a user
        user = Auth.register_user('testuser', 'test@example.com', 'password123')
        
        # Create a verification request
        requester_did = "did:example:requester"
        subject_did = "did:example:subject"
        requested_attributes = ["name", "age", "email"]
        
        request = Auth.request_disclosure(
            requester_did=requester_did,
            subject_did=subject_did,
            requested_attributes=requested_attributes,
            user_id=user.id
        )
        
        # Check request creation
        assert request is not None
        assert "request_id" in request
        assert request["requester_did"] == requester_did
        assert request["subject_did"] == subject_did
        assert request["requested_attributes"] == requested_attributes
        assert request["status"] == "pending"
        
        # Respond to the request
        request_id = request["request_id"]
        disclosed_attributes = {
            "name": "John Doe",
            "email": "john@example.com"
            # Note: age is not disclosed
        }
        
        response = Auth.respond_to_disclosure_request(
            request_id=request_id,
            subject_did=subject_did,
            disclosed_attributes=disclosed_attributes,
            user_id=user.id
        )
        
        # Check response
        assert response is not None
        assert response["request_id"] == request_id
        assert response["requester_did"] == requester_did
        assert response["subject_did"] == subject_did
        assert response["status"] == "approved"
        assert response["disclosed_attributes"] == disclosed_attributes
        
        # Verify in the database
        db_request = VerificationRequest.query.filter_by(request_id=request_id).first()
        assert db_request is not None
        assert db_request.status == "approved"
        
        # Test rejecting a request
        new_request = Auth.request_disclosure(
            requester_did=requester_did,
            subject_did=subject_did,
            requested_attributes=["ssn", "bankAccount"],
            user_id=user.id
        )
        
        rejection = Auth.reject_disclosure_request(
            request_id=new_request["request_id"],
            subject_did=subject_did,
            reason="Too sensitive information requested"
        )
        
        # Check rejection
        assert rejection is not None
        assert rejection["status"] == "rejected"
        assert rejection["reason"] == "Too sensitive information requested"
        
        # Verify in the database
        db_rejection = VerificationRequest.query.filter_by(request_id=new_request["request_id"]).first()
        assert db_rejection is not None
        assert db_rejection.status == "rejected"
