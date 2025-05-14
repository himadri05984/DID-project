import os
import json
import uuid
import base64
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import logging

from models import DID, db

logger = logging.getLogger(__name__)

class DIDWallet:
    """
    Handles the creation and management of Decentralized Identifiers (DIDs)
    and their associated cryptographic key pairs
    """
    
    @staticmethod
    def generate_key_pair():
        """
        Generate an RSA key pair for DID
        
        Returns:
            tuple: (private_key_pem, public_key_pem)
        """
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Get public key from private key
        public_key = private_key.public_key()
        
        # Serialize private key to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        # Serialize public key to PEM format
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return private_key_pem, public_key_pem

    @staticmethod
    def create_did(user_id, method="ethr"):
        """
        Create a new DID for a user
        
        Args:
            user_id (int): ID of the user creating the DID
            method (str): DID method (e.g., "ethr", "web")
            
        Returns:
            dict: The created DID document
        """
        try:
            # Generate key pair
            private_key_pem, public_key_pem = DIDWallet.generate_key_pair()
            
            # Generate a unique DID identifier
            did_id = f"did:{method}:{uuid.uuid4().hex}"
            
            # Create the DID document
            current_time = datetime.utcnow().isoformat() + "Z"
            
            # Public key ID within the DID document
            key_id = f"{did_id}#keys-1"
            
            did_document = {
                "@context": "https://www.w3.org/ns/did/v1",
                "id": did_id,
                "created": current_time,
                "updated": current_time,
                "verificationMethod": [
                    {
                        "id": key_id,
                        "type": "RsaVerificationKey2018",
                        "controller": did_id,
                        "publicKeyPem": public_key_pem
                    }
                ],
                "authentication": [key_id],
                "assertionMethod": [key_id]
            }
            
            # Store the DID in the database
            new_did = DID(
                did_id=did_id,
                method=method,
                user_id=user_id,
                public_key=public_key_pem,
                private_key=private_key_pem,  # In production, this should be encrypted
                document=json.dumps(did_document)
            )
            
            db.session.add(new_did)
            db.session.commit()
            
            logger.info(f"Created new DID: {did_id} for user {user_id}")
            
            return did_document
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating DID: {str(e)}")
            raise

    @staticmethod
    def get_did_document(did_id):
        """
        Retrieve a DID document by its ID
        
        Args:
            did_id (str): The DID identifier
            
        Returns:
            dict: The DID document or None if not found
        """
        did = DID.query.filter_by(did_id=did_id).first()
        if did:
            return json.loads(did.document)
        return None

    @staticmethod
    def list_user_dids(user_id):
        """
        List all DIDs for a specific user
        
        Args:
            user_id (int): The user ID
            
        Returns:
            list: List of DIDs for the user
        """
        dids = DID.query.filter_by(user_id=user_id, active=True).all()
        return [json.loads(did.document) for did in dids]

    @staticmethod
    def deactivate_did(did_id, user_id):
        """
        Deactivate a DID
        
        Args:
            did_id (str): The DID identifier
            user_id (int): The user ID for verification
            
        Returns:
            bool: True if successful, False otherwise
        """
        did = DID.query.filter_by(did_id=did_id, user_id=user_id).first()
        if did:
            did.active = False
            did.updated_at = datetime.utcnow()
            
            # Update the DID document to reflect deactivation
            document = json.loads(did.document)
            document["deactivated"] = True
            document["updated"] = datetime.utcnow().isoformat() + "Z"
            did.document = json.dumps(document)
            
            db.session.commit()
            logger.info(f"Deactivated DID: {did_id}")
            return True
        
        logger.warning(f"Failed to deactivate DID: {did_id} - not found or not owned by user {user_id}")
        return False

    @staticmethod
    def sign_data(did_id, user_id, data):
        """
        Sign data using the private key associated with a DID
        
        Args:
            did_id (str): The DID identifier
            user_id (int): The user ID for verification
            data (dict/str): The data to sign
            
        Returns:
            str: Base64-encoded signature
        """
        try:
            # Get the DID and associated private key
            did = DID.query.filter_by(did_id=did_id, user_id=user_id, active=True).first()
            if not did:
                raise ValueError(f"DID {did_id} not found or not active")
            
            # Convert data to JSON string if it's a dict
            message = json.dumps(data) if isinstance(data, dict) else data
            message_bytes = message.encode('utf-8')
            
            # Load the private key
            private_key = serialization.load_pem_private_key(
                did.private_key.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            
            # Sign the data
            signature = private_key.sign(
                message_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            # Return base64 encoded signature
            return base64.b64encode(signature).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Error signing data with DID {did_id}: {str(e)}")
            raise

    @staticmethod
    def verify_signature(did_id, data, signature):
        """
        Verify a signature using the public key associated with a DID
        
        Args:
            did_id (str): The DID identifier
            data (dict/str): The signed data
            signature (str): Base64-encoded signature
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            # Get the DID and associated public key
            did = DID.query.filter_by(did_id=did_id).first()
            if not did:
                raise ValueError(f"DID {did_id} not found")
            
            # Convert data to JSON string if it's a dict
            message = json.dumps(data) if isinstance(data, dict) else data
            message_bytes = message.encode('utf-8')
            
            # Decode the signature
            signature_bytes = base64.b64decode(signature)
            
            # Load the public key
            public_key = serialization.load_pem_public_key(
                did.public_key.encode('utf-8'),
                backend=default_backend()
            )
            
            # Verify the signature
            try:
                public_key.verify(
                    signature_bytes,
                    message_bytes,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                return True
            except Exception:
                return False
                
        except Exception as e:
            logger.error(f"Error verifying signature for DID {did_id}: {str(e)}")
            return False
