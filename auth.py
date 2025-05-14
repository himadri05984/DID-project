import json
import uuid
import os
import base64
import logging
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user
import jwt

from models import User, DID, VerificationRequest, db
from wallet import DIDWallet

logger = logging.getLogger(__name__)

class Auth:
    """
    Handles authentication and authorization for the DID system
    """
    
    JWT_SECRET = os.environ.get("JWT_SECRET", "default_jwt_secret")
    
    @staticmethod
    def register_user(username, email, password):
        """
        Register a new user in the system
        
        Args:
            username (str): User's username
            email (str): User's email
            password (str): User's password
            
        Returns:
            User: The created user object or None if registration failed
        """
        try:
            # Check if user already exists
            existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
            if existing_user:
                logger.warning(f"User registration failed: username or email already exists")
                return None
                
            # Create new user
            new_user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password)
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            logger.info(f"User registered successfully: {username}")
            return new_user
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error registering user: {str(e)}")
            return None
    
    @staticmethod
    def login(username_or_email, password):
        """
        Authenticate a user with username/email and password
        
        Args:
            username_or_email (str): User's username or email
            password (str): User's password
            
        Returns:
            User: The authenticated user or None if authentication failed
        """
        try:
            # Find user by username or email
            user = User.query.filter(
                (User.username == username_or_email) | (User.email == username_or_email)
            ).first()
            
            if not user or not check_password_hash(user.password_hash, password):
                logger.warning(f"Login failed: invalid credentials for {username_or_email}")
                return None
                
            # Login the user with Flask-Login
            login_user(user)
            
            logger.info(f"User logged in successfully: {user.username}")
            return user
            
        except Exception as e:
            logger.error(f"Error during login: {str(e)}")
            return None
    
    @staticmethod
    def logout():
        """
        Log out the current user
        
        Returns:
            bool: True if logout was successful
        """
        try:
            logout_user()
            logger.info("User logged out successfully")
            return True
        except Exception as e:
            logger.error(f"Error during logout: {str(e)}")
            return False
    
    @staticmethod
    def did_auth_challenge(did_id):
        """
        Generate a DID authentication challenge
        
        Args:
            did_id (str): The DID to authenticate
            
        Returns:
            dict: Challenge data including a nonce
        """
        # Generate a random challenge nonce
        nonce = base64.b64encode(os.urandom(32)).decode('utf-8')
        
        # Create a challenge object
        challenge = {
            "type": "DIDAuthChallenge",
            "did": did_id,
            "nonce": nonce,
            "created": datetime.utcnow().isoformat(),
            "expires": (datetime.utcnow() + timedelta(minutes=5)).isoformat()
        }
        
        # In a real implementation, we would store this challenge
        # For simplicity, we'll encode it in a JWT
        token = jwt.encode(challenge, Auth.JWT_SECRET, algorithm="HS256")
        
        return {
            "challenge": challenge,
            "token": token
        }
    
    @staticmethod
    def verify_did_auth_response(response):
        """
        Verify a DID authentication response
        
        Args:
            response (dict): The authentication response
            
        Returns:
            bool: True if authentication is successful
        """
        try:
            # Extract the challenge token
            token = response.get("token")
            if not token:
                logger.warning("Missing challenge token in auth response")
                return False
                
            # Decode and verify the token
            try:
                challenge = jwt.decode(token, Auth.JWT_SECRET, algorithms=["HS256"])
            except jwt.InvalidTokenError:
                logger.warning("Invalid challenge token")
                return False
                
            # Verify the response matches the challenge
            did_id = challenge.get("did")
            nonce = challenge.get("nonce")
            
            # Check if challenge has expired
            expires = datetime.fromisoformat(challenge.get("expires").replace('Z', '+00:00'))
            if datetime.utcnow() > expires:
                logger.warning("Challenge has expired")
                return False
                
            # Verify the signature using DID wallet
            signature = response.get("signature")
            signed_data = {
                "did": did_id,
                "nonce": nonce,
                "timestamp": response.get("timestamp")
            }
            
            if not DIDWallet.verify_signature(did_id, signed_data, signature):
                logger.warning("Invalid signature in auth response")
                return False
                
            logger.info(f"DID authentication successful for {did_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error during DID authentication: {str(e)}")
            return False
    
    @staticmethod
    def request_disclosure(requester_did, subject_did, requested_attributes, user_id):
        """
        Create a verification request for selective disclosure
        
        Args:
            requester_did (str): DID of the requester
            subject_did (str): DID of the subject (credential holder)
            requested_attributes (list): List of requested attributes
            user_id (int): ID of the user making the request
            
        Returns:
            dict: The created verification request
        """
        try:
            # Create a unique request ID
            request_id = str(uuid.uuid4())
            
            # Structure the request data
            request_data = {
                "type": "VerificationRequest",
                "requestedAttributes": requested_attributes
            }
            
            # Create the verification request record
            verification_request = VerificationRequest(
                request_id=request_id,
                requester_did=requester_did,
                subject_did=subject_did,
                user_id=user_id,
                requested_data=json.dumps(request_data),
                status="pending"
            )
            
            db.session.add(verification_request)
            db.session.commit()
            
            logger.info(f"Created verification request {request_id} from {requester_did} to {subject_did}")
            
            return {
                "request_id": request_id,
                "requester_did": requester_did,
                "subject_did": subject_did,
                "requested_attributes": requested_attributes,
                "status": "pending",
                "created_at": verification_request.request_date.isoformat()
            }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating verification request: {str(e)}")
            raise
    
    @staticmethod
    def respond_to_disclosure_request(request_id, subject_did, disclosed_attributes, user_id):
        """
        Respond to a verification request with selectively disclosed attributes
        
        Args:
            request_id (str): ID of the verification request
            subject_did (str): DID of the subject (credential holder)
            disclosed_attributes (dict): The attributes to disclose
            user_id (int): ID of the user responding to the request
            
        Returns:
            dict: The updated verification request
        """
        try:
            # Find the verification request
            verification_request = VerificationRequest.query.filter_by(
                request_id=request_id,
                subject_did=subject_did
            ).first()
            
            if not verification_request:
                logger.warning(f"Verification request {request_id} not found")
                return None
                
            # Update the request with the disclosed data
            verification_request.status = "approved"
            verification_request.response_date = datetime.utcnow()
            verification_request.disclosed_data = json.dumps(disclosed_attributes)
            
            db.session.commit()
            
            logger.info(f"Responded to verification request {request_id}")
            
            return {
                "request_id": request_id,
                "requester_did": verification_request.requester_did,
                "subject_did": subject_did,
                "status": "approved",
                "response_date": verification_request.response_date.isoformat(),
                "disclosed_attributes": disclosed_attributes
            }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error responding to verification request: {str(e)}")
            raise
    
    @staticmethod
    def reject_disclosure_request(request_id, subject_did, reason=None):
        """
        Reject a verification request
        
        Args:
            request_id (str): ID of the verification request
            subject_did (str): DID of the subject
            reason (str, optional): Reason for rejection
            
        Returns:
            dict: The updated verification request
        """
        try:
            # Find the verification request
            verification_request = VerificationRequest.query.filter_by(
                request_id=request_id,
                subject_did=subject_did
            ).first()
            
            if not verification_request:
                logger.warning(f"Verification request {request_id} not found")
                return None
                
            # Update the request status
            verification_request.status = "rejected"
            verification_request.response_date = datetime.utcnow()
            if reason:
                verification_request.disclosed_data = json.dumps({"rejection_reason": reason})
            
            db.session.commit()
            
            logger.info(f"Rejected verification request {request_id}")
            
            return {
                "request_id": request_id,
                "requester_did": verification_request.requester_did,
                "subject_did": subject_did,
                "status": "rejected",
                "response_date": verification_request.response_date.isoformat(),
                "reason": reason
            }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error rejecting verification request: {str(e)}")
            raise
