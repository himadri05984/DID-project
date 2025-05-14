import json
import logging
import uuid
import base64
from datetime import datetime

logger = logging.getLogger(__name__)

class DIDUtils:
    """
    Utility functions for DID operations
    """
    
    @staticmethod
    def parse_did(did):
        """
        Parse a DID into its components
        
        Args:
            did (str): The DID to parse
            
        Returns:
            dict: The parsed components or None if invalid
        """
        try:
            if not did.startswith("did:"):
                return None
                
            parts = did.split(":")
            if len(parts) < 3:
                return None
                
            return {
                "did": did,
                "method": parts[1],
                "id": ":".join(parts[2:])
            }
        except Exception as e:
            logger.error(f"Error parsing DID {did}: {str(e)}")
            return None
    
    @staticmethod
    def validate_credential_schema(credential_data, schema_type=None):
        """
        Validate a credential against a schema
        
        Args:
            credential_data (dict): The credential to validate
            schema_type (str, optional): Type of schema to validate against
            
        Returns:
            bool: True if valid, False otherwise
        """
        # Basic validation for required fields in W3C VC data model
        required_fields = ["@context", "id", "type", "issuer", "issuanceDate", "credentialSubject"]
        
        for field in required_fields:
            if field not in credential_data:
                logger.warning(f"Credential missing required field: {field}")
                return False
        
        # Check if credential has a subject with an id
        subject = credential_data.get("credentialSubject", {})
        if not isinstance(subject, dict) or "id" not in subject:
            logger.warning("Credential subject missing or does not have an id")
            return False
            
        # Validate the credential types
        types = credential_data.get("type", [])
        if not isinstance(types, list) or "VerifiableCredential" not in types:
            logger.warning("Credential must have 'VerifiableCredential' in its type array")
            return False
            
        # If a specific schema type is provided, do more detailed validation
        if schema_type:
            # In a production system, we would implement schema-specific validation here
            # For example, validating against JSON Schema definitions
            pass
            
        return True
    
    @staticmethod
    def format_did_document(did_doc):
        """
        Format a DID document for display
        
        Args:
            did_doc (dict): The DID document to format
            
        Returns:
            str: Formatted DID document as a string
        """
        try:
            return json.dumps(did_doc, indent=2)
        except Exception:
            return str(did_doc)
    
    @staticmethod
    def generate_challenge_nonce():
        """
        Generate a random challenge nonce for authentication
        
        Returns:
            str: Base64-encoded random nonce
        """
        return base64.b64encode(uuid.uuid4().bytes).decode('utf-8')
    
    @staticmethod
    def format_timestamp(timestamp):
        """
        Format a timestamp for display
        
        Args:
            timestamp (str/datetime): The timestamp to format
            
        Returns:
            str: Formatted timestamp
        """
        if isinstance(timestamp, str):
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except ValueError:
                return timestamp
        elif isinstance(timestamp, datetime):
            dt = timestamp
        else:
            return str(timestamp)
            
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    
    @staticmethod
    def get_credential_types():
        """
        Get a list of supported credential types
        
        Returns:
            list: Supported credential types
        """
        return [
            {
                "id": "UniversityDegree",
                "name": "University Degree",
                "description": "Academic degree awarded by a university",
                "attributes": ["degreeName", "degreeType", "university", "graduationDate", "fieldOfStudy"]
            },
            {
                "id": "EmploymentCredential",
                "name": "Employment Credential",
                "description": "Proof of employment at an organization",
                "attributes": ["employer", "jobTitle", "startDate", "endDate", "department"]
            },
            {
                "id": "DriverLicense",
                "name": "Driver's License",
                "description": "Government-issued driver's license",
                "attributes": ["licenseNumber", "issuingAuthority", "issuingCountry", "validFrom", "validUntil", "vehicleCategories"]
            },
            {
                "id": "MembershipCredential",
                "name": "Membership Credential",
                "description": "Proof of membership in an organization",
                "attributes": ["organization", "membershipId", "membershipLevel", "joinDate", "validUntil"]
            },
            {
                "id": "HealthCredential",
                "name": "Health Credential",
                "description": "Health-related certification",
                "attributes": ["healthProvider", "certificationType", "issueDate", "expiryDate"]
            }
        ]
