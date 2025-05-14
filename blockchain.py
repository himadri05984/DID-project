import os
import json
import logging
import uuid
from datetime import datetime
from web3 import Web3
from models import DID, Credential, Revocation, db

logger = logging.getLogger(__name__)

class BlockchainIntegration:
    """
    Handles interactions with the Ethereum blockchain for 
    anchoring DIDs and verifiable credentials
    """
    
    def __init__(self):
        # Initialize Web3 connection
        try:
            # Use Infura by default, but allow configuration through environment variable
            infura_key = os.environ.get("INFURA_API_KEY", "")
            self.w3 = Web3(Web3.HTTPProvider(
                f"https://mainnet.infura.io/v3/{infura_key}" if infura_key else
                os.environ.get("ETHEREUM_RPC_URL", "http://localhost:8545")
            ))
            
            # For development, check if we need to connect to a test network
            if os.environ.get("USE_TEST_NETWORK", "false").lower() == "true":
                self.w3 = Web3(Web3.HTTPProvider(
                    f"https://sepolia.infura.io/v3/{infura_key}" if infura_key else
                    os.environ.get("ETHEREUM_TEST_RPC_URL", "http://localhost:8545")
                ))
            
            # Check connection
            if not self.w3.is_connected():
                logger.warning("Failed to connect to Ethereum node, blockchain features will be simulated")
                self.connected = False
            else:
                self.connected = True
                logger.info(f"Connected to Ethereum node, chain ID: {self.w3.eth.chain_id}")
                
            # Get private key for transactions from environment (for signing transactions)
            self.private_key = os.environ.get("ETHEREUM_PRIVATE_KEY", "")
            if not self.private_key and self.connected:
                logger.warning("No Ethereum private key provided, transactions will be simulated")
                
        except Exception as e:
            logger.error(f"Error initializing blockchain connection: {str(e)}")
            self.connected = False
    
    def anchor_did_on_chain(self, did_id, user_id):
        """
        Anchor a DID on the Ethereum blockchain by storing its hash
        
        Args:
            did_id (str): The DID identifier
            user_id (int): User ID for verification
            
        Returns:
            str: Transaction hash or None if failed
        """
        did = DID.query.filter_by(did_id=did_id, user_id=user_id).first()
        if not did:
            logger.error(f"DID {did_id} not found or not owned by user {user_id}")
            return None
            
        # In a real implementation, we would use a smart contract for storing DIDs
        # For now, we'll simulate the process by generating a transaction hash
        if not self.connected or not self.private_key:
            # Simulate blockchain anchoring
            tx_hash = f"0x{uuid.uuid4().hex}"
            logger.info(f"Simulated anchoring DID {did_id} with tx_hash: {tx_hash}")
        else:
            try:
                # In a real implementation, we would call a smart contract method
                # For now, we'll just log the attempt but return a simulated hash
                logger.info(f"Would anchor DID {did_id} on chain, but using simulation for demo")
                tx_hash = f"0x{uuid.uuid4().hex}"
            except Exception as e:
                logger.error(f"Error anchoring DID on chain: {str(e)}")
                return None
        
        # Update the DID record with the transaction hash
        did.blockchain_tx_hash = tx_hash
        db.session.commit()
        
        return tx_hash
        
    def verify_did_on_chain(self, did_id):
        """
        Verify if a DID is anchored on the blockchain
        
        Args:
            did_id (str): The DID identifier
            
        Returns:
            dict: Verification result with status and details
        """
        did = DID.query.filter_by(did_id=did_id).first()
        if not did or not did.blockchain_tx_hash:
            return {"verified": False, "reason": "DID not anchored on blockchain"}
            
        # In a real implementation, we would query the blockchain
        # For now, we'll just check if there's a transaction hash recorded
        return {
            "verified": True,
            "tx_hash": did.blockchain_tx_hash,
            "timestamp": did.updated_at.isoformat()
        }
        
    def anchor_credential(self, credential_id, user_id):
        """
        Anchor a verifiable credential on the blockchain
        
        Args:
            credential_id (str): The credential identifier
            user_id (int): User ID for verification
            
        Returns:
            str: Transaction hash or None if failed
        """
        credential = Credential.query.filter_by(credential_id=credential_id).first()
        if not credential:
            logger.error(f"Credential {credential_id} not found")
            return None
            
        # Similarly as with DIDs, we'd use a smart contract in a real implementation
        if not self.connected or not self.private_key:
            # Simulate blockchain anchoring
            tx_hash = f"0x{uuid.uuid4().hex}"
            logger.info(f"Simulated anchoring credential {credential_id} with tx_hash: {tx_hash}")
        else:
            try:
                # Simulate for now
                logger.info(f"Would anchor credential {credential_id} on chain, but using simulation for demo")
                tx_hash = f"0x{uuid.uuid4().hex}"
            except Exception as e:
                logger.error(f"Error anchoring credential on chain: {str(e)}")
                return None
        
        # Update the credential with the blockchain proof
        credential.blockchain_proof = tx_hash
        db.session.commit()
        
        return tx_hash
        
    def register_revocation(self, credential_id, issuer_did, reason=None):
        """
        Register the revocation of a credential on the blockchain
        
        Args:
            credential_id (str): The credential identifier
            issuer_did (str): DID of the issuer
            reason (str, optional): Reason for revocation
            
        Returns:
            str: Transaction hash or None if failed
        """
        # Find the credential and verify it exists
        credential = Credential.query.filter_by(credential_id=credential_id, issuer_did=issuer_did).first()
        if not credential:
            logger.error(f"Credential {credential_id} not found or not issued by {issuer_did}")
            return None
            
        # Mark the credential as revoked
        credential.revoked = True
        credential.revocation_date = datetime.utcnow()
        
        # Similarly as with DIDs, we'd use a smart contract for revocations
        if not self.connected or not self.private_key:
            # Simulate blockchain revocation
            tx_hash = f"0x{uuid.uuid4().hex}"
            logger.info(f"Simulated registering revocation for credential {credential_id} with tx_hash: {tx_hash}")
        else:
            try:
                # Simulate for now
                logger.info(f"Would register revocation on chain, but using simulation for demo")
                tx_hash = f"0x{uuid.uuid4().hex}"
            except Exception as e:
                logger.error(f"Error registering revocation on chain: {str(e)}")
                return None
        
        # Create revocation record
        revocation = Revocation(
            credential_id=credential_id,
            issuer_did=issuer_did,
            reason=reason,
            blockchain_tx_hash=tx_hash
        )
        
        db.session.add(revocation)
        db.session.commit()
        
        return tx_hash
        
    def check_revocation_status(self, credential_id):
        """
        Check if a credential has been revoked
        
        Args:
            credential_id (str): The credential identifier
            
        Returns:
            dict: Revocation status with details
        """
        # First check the local database
        credential = Credential.query.filter_by(credential_id=credential_id).first()
        if not credential:
            return {"error": "Credential not found"}
            
        revocation = Revocation.query.filter_by(credential_id=credential_id).first()
        
        if credential.revoked:
            return {
                "revoked": True,
                "revocation_date": credential.revocation_date.isoformat() if credential.revocation_date else None,
                "reason": revocation.reason if revocation else "No reason provided",
                "tx_hash": revocation.blockchain_tx_hash if revocation else None
            }
        
        # In a real implementation, we would also check the blockchain
        return {"revoked": False}
