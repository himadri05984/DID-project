import json
import uuid
import logging
from datetime import datetime

from models import Credential, DID, db
from wallet import DIDWallet
from blockchain import BlockchainIntegration

logger = logging.getLogger(__name__)

class CredentialManager:
    """
    Handles the creation, verification, and management of Verifiable Credentials
    """
    
    @staticmethod
    def issue_credential(issuer_did, holder_did, credential_type, claims, expiration_date=None, user_id=None):
        """
        Issue a new verifiable credential
        
        Args:
            issuer_did (str): DID of the issuer
            holder_did (str): DID of the credential holder
            credential_type (str): Type of credential (e.g., "UniversityDegree")
            claims (dict): Credential claims/attributes
            expiration_date (datetime, optional): Expiration date of the credential
            user_id (int, optional): User ID of the issuer
            
        Returns:
            dict: The issued credential or None if issuance fails
        """
        try:
            # Verify issuer DID exists
            issuer = DID.query.filter_by(did_id=issuer_did, active=True).first()
            if not issuer:
                logger.error(f"Issuer DID {issuer_did} not found or not active")
                return None
                
            # If user_id is provided, verify ownership of the issuer DID
            if user_id and issuer.user_id != user_id:
                logger.error(f"User {user_id} does not own DID {issuer_did}")
                return None
            
            # Generate a unique credential ID
            credential_id = f"vc:{uuid.uuid4().hex}"
            
            # Create credential data following W3C Verifiable Credentials Data Model
            issuance_date = datetime.utcnow()
            
            credential_data = {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1"
                ],
                "id": credential_id,
                "type": ["VerifiableCredential", credential_type],
                "issuer": issuer_did,
                "issuanceDate": issuance_date.isoformat() + "Z",
                "credentialSubject": {
                    "id": holder_did,
                    **claims
                }
            }
            
            # Add expiration date if provided
            if expiration_date:
                credential_data["expirationDate"] = expiration_date.isoformat() + "Z"
            
            # Sign the credential using the issuer's DID
            signature = DIDWallet.sign_data(issuer_did, issuer.user_id, credential_data)
            
            # Add proof to the credential
            credential_data["proof"] = {
                "type": "RsaSignature2018",
                "created": issuance_date.isoformat() + "Z",
                "proofPurpose": "assertionMethod",
                "verificationMethod": f"{issuer_did}#keys-1",
                "jws": signature
            }
            
            # Store the credential in the database
            new_credential = Credential(
                credential_id=credential_id,
                issuer_did=issuer_did,
                holder_did=holder_did,
                user_id=issuer.user_id,  # Associate with the issuer's user account
                type=credential_type,
                expiration_date=expiration_date,
                credential_data=json.dumps(credential_data)
            )
            
            db.session.add(new_credential)
            db.session.commit()
            
            logger.info(f"Issued credential {credential_id} from {issuer_did} to {holder_did}")
            
            # Optionally anchor the credential on the blockchain
            blockchain = BlockchainIntegration()
            tx_hash = blockchain.anchor_credential(credential_id, issuer.user_id)
            if tx_hash:
                logger.info(f"Anchored credential {credential_id} on blockchain with tx_hash: {tx_hash}")
                
                # Update the credential with the blockchain proof
                new_credential.blockchain_proof = tx_hash
                db.session.commit()
                
                # Add blockchain proof to the credential data
                credential_data["proof"]["blockchainProof"] = {
                    "type": "EthereumTransaction",
                    "transactionHash": tx_hash
                }
            
            return credential_data
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error issuing credential: {str(e)}")
            return None
    
    @staticmethod
    def verify_credential(credential_data):
        """
        Verify a credential's authenticity and validity
        
        Args:
            credential_data (dict): The credential to verify
            
        Returns:
            dict: Verification result with status and details
        """
        try:
            # Extract credential details
            credential_id = credential_data.get("id")
            issuer_did = credential_data.get("issuer")
            holder_did = credential_data.get("credentialSubject", {}).get("id")
            proof = credential_data.get("proof", {})
            
            if not credential_id or not issuer_did or not holder_did or not proof:
                return {"verified": False, "reason": "Missing required credential fields"}
                
            # Check if credential is in the database
            credential_record = Credential.query.filter_by(credential_id=credential_id).first()
            if credential_record and credential_record.revoked:
                return {"verified": False, "reason": "Credential has been revoked"}
                
            # Check expiration
            if "expirationDate" in credential_data:
                try:
                    expiration_date = datetime.fromisoformat(credential_data["expirationDate"].replace('Z', '+00:00'))
                    if datetime.utcnow() > expiration_date:
                        return {"verified": False, "reason": "Credential has expired"}
                except (ValueError, TypeError):
                    return {"verified": False, "reason": "Invalid expiration date format"}
            
            # Verify the signature
            # Make a copy of the credential data without the proof
            credential_data_without_proof = credential_data.copy()
            credential_data_without_proof.pop("proof", None)
            
            # Extract the signature (JWS) from the proof
            signature = proof.get("jws")
            if not signature:
                return {"verified": False, "reason": "Missing signature in proof"}
                
            # Verify the signature using the issuer's DID
            if not DIDWallet.verify_signature(issuer_did, credential_data_without_proof, signature):
                return {"verified": False, "reason": "Invalid signature"}
                
            # Optionally verify blockchain proof
            blockchain_verified = False
            if "blockchainProof" in proof:
                blockchain = BlockchainIntegration()
                if credential_record and credential_record.blockchain_proof:
                    blockchain_verified = True
            
            return {
                "verified": True,
                "issuer": issuer_did,
                "holder": holder_did,
                "blockchain_verified": blockchain_verified,
                "credential_id": credential_id
            }
            
        except Exception as e:
            logger.error(f"Error verifying credential: {str(e)}")
            return {"verified": False, "reason": f"Verification error: {str(e)}"}
    
    @staticmethod
    def get_credential(credential_id):
        """
        Retrieve a credential by its ID
        
        Args:
            credential_id (str): The credential identifier
            
        Returns:
            dict: The credential data or None if not found
        """
        credential = Credential.query.filter_by(credential_id=credential_id).first()
        if credential:
            return json.loads(credential.credential_data)
        return None
    
    @staticmethod
    def list_user_credentials(user_id, as_holder=True):
        """
        List all credentials for a specific user, either as holder or issuer
        
        Args:
            user_id (int): The user ID
            as_holder (bool): If True, list credentials where user is the holder,
                              otherwise list credentials issued by the user
            
        Returns:
            list: List of credentials
        """
        # Get user's DIDs
        user_dids = DID.query.filter_by(user_id=user_id).all()
        user_did_ids = [did.did_id for did in user_dids]
        
        if not user_did_ids:
            return []
            
        if as_holder:
            # Find credentials where user is the holder
            credentials = Credential.query.filter(
                Credential.holder_did.in_(user_did_ids)
            ).all()
        else:
            # Find credentials issued by the user
            credentials = Credential.query.filter(
                Credential.issuer_did.in_(user_did_ids)
            ).all()
            
        return [json.loads(credential.credential_data) for credential in credentials]
    
    @staticmethod
    def revoke_credential(credential_id, issuer_did, user_id, reason=None):
        """
        Revoke a credential
        
        Args:
            credential_id (str): The credential identifier
            issuer_did (str): DID of the issuer
            user_id (int): User ID for verification
            reason (str, optional): Reason for revocation
            
        Returns:
            bool: True if revocation is successful
        """
        try:
            # Find the credential
            credential = Credential.query.filter_by(
                credential_id=credential_id,
                issuer_did=issuer_did
            ).first()
            
            if not credential:
                logger.error(f"Credential {credential_id} not found or not issued by {issuer_did}")
                return False
                
            # Verify that the user owns the issuer DID
            issuer = DID.query.filter_by(did_id=issuer_did, user_id=user_id).first()
            if not issuer:
                logger.error(f"User {user_id} does not own issuer DID {issuer_did}")
                return False
                
            # Register revocation on blockchain
            blockchain = BlockchainIntegration()
            tx_hash = blockchain.register_revocation(credential_id, issuer_did, reason)
            
            if tx_hash:
                logger.info(f"Revoked credential {credential_id} with blockchain tx_hash: {tx_hash}")
                return True
            else:
                logger.error(f"Failed to register revocation for credential {credential_id}")
                return False
                
        except Exception as e:
            logger.error(f"Error revoking credential: {str(e)}")
            return False
    
    @staticmethod
    def create_presentation(credential_ids, holder_did, user_id, verifier_did, disclosed_attributes=None):
        """
        Create a verifiable presentation with selective disclosure
        
        Args:
            credential_ids (list): List of credential IDs to include
            holder_did (str): DID of the presentation holder
            user_id (int): User ID for verification
            verifier_did (str): DID of the intended verifier
            disclosed_attributes (dict, optional): Map of credential ID to list of attributes to disclose
            
        Returns:
            dict: The created presentation
        """
        try:
            # Verify that the user owns the holder DID
            holder = DID.query.filter_by(did_id=holder_did, user_id=user_id).first()
            if not holder:
                logger.error(f"User {user_id} does not own holder DID {holder_did}")
                return None
                
            # Create presentation ID
            presentation_id = f"vp:{uuid.uuid4().hex}"
            created_date = datetime.utcnow()
            
            # Initialize presentation structure
            presentation = {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "id": presentation_id,
                "type": ["VerifiablePresentation"],
                "holder": holder_did,
                "verifier": verifier_did,
                "created": created_date.isoformat() + "Z",
                "verifiableCredential": []
            }
            
            # Add credentials with selective disclosure
            for credential_id in credential_ids:
                credential_data = CredentialManager.get_credential(credential_id)
                if not credential_data:
                    logger.warning(f"Credential {credential_id} not found, skipping")
                    continue
                    
                # Check if this credential belongs to the holder
                if credential_data.get("credentialSubject", {}).get("id") != holder_did:
                    logger.warning(f"Credential {credential_id} does not belong to holder {holder_did}, skipping")
                    continue
                
                # Apply selective disclosure if specified
                if disclosed_attributes and credential_id in disclosed_attributes:
                    # Create a copy of the credential with only the specified attributes
                    filtered_credential = credential_data.copy()
                    
                    # Get the list of attributes to disclose
                    attributes_to_disclose = disclosed_attributes[credential_id]
                    
                    # Filter the credential subject to only include specified attributes
                    original_subject = credential_data.get("credentialSubject", {})
                    filtered_subject = {"id": original_subject.get("id")}
                    
                    for attr in attributes_to_disclose:
                        if attr in original_subject:
                            filtered_subject[attr] = original_subject[attr]
                    
                    filtered_credential["credentialSubject"] = filtered_subject
                    
                    # Add metadata to indicate selective disclosure
                    filtered_credential["_selective_disclosure"] = {
                        "disclosed_attributes": attributes_to_disclose,
                        "total_attributes": len(original_subject) - 1  # Subtract 1 for the ID
                    }
                    
                    presentation["verifiableCredential"].append(filtered_credential)
                else:
                    # Include the full credential
                    presentation["verifiableCredential"].append(credential_data)
            
            # Sign the presentation
            signature = DIDWallet.sign_data(holder_did, user_id, presentation)
            
            # Add proof to the presentation
            presentation["proof"] = {
                "type": "RsaSignature2018",
                "created": created_date.isoformat() + "Z",
                "proofPurpose": "authentication",
                "verificationMethod": f"{holder_did}#keys-1",
                "jws": signature
            }
            
            return presentation
            
        except Exception as e:
            logger.error(f"Error creating presentation: {str(e)}")
            return None
    
    @staticmethod
    def verify_presentation(presentation):
        """
        Verify a verifiable presentation
        
        Args:
            presentation (dict): The presentation to verify
            
        Returns:
            dict: Verification result with status and details
        """
        try:
            # Extract presentation details
            holder_did = presentation.get("holder")
            credentials = presentation.get("verifiableCredential", [])
            proof = presentation.get("proof", {})
            
            if not holder_did or not credentials or not proof:
                return {"verified": False, "reason": "Missing required presentation fields"}
            
            # Verify the presentation signature
            presentation_without_proof = presentation.copy()
            presentation_without_proof.pop("proof", None)
            
            signature = proof.get("jws")
            if not signature:
                return {"verified": False, "reason": "Missing signature in presentation proof"}
                
            if not DIDWallet.verify_signature(holder_did, presentation_without_proof, signature):
                return {"verified": False, "reason": "Invalid presentation signature"}
            
            # Verify each credential in the presentation
            verified_credentials = []
            failed_credentials = []
            
            for credential in credentials:
                # Check if it's a selectively disclosed credential
                is_selective = "_selective_disclosure" in credential
                
                verification_result = CredentialManager.verify_credential(credential)
                
                if verification_result.get("verified"):
                    verified_credentials.append({
                        "credential_id": credential.get("id"),
                        "is_selective_disclosure": is_selective,
                        "issuer": verification_result.get("issuer")
                    })
                else:
                    failed_credentials.append({
                        "credential_id": credential.get("id"),
                        "reason": verification_result.get("reason")
                    })
            
            return {
                "verified": len(failed_credentials) == 0 and len(verified_credentials) > 0,
                "holder": holder_did,
                "credentials_verified": len(verified_credentials),
                "credentials_failed": len(failed_credentials),
                "verified_credentials": verified_credentials,
                "failed_credentials": failed_credentials
            }
            
        except Exception as e:
            logger.error(f"Error verifying presentation: {str(e)}")
            return {"verified": False, "reason": f"Verification error: {str(e)}"}
