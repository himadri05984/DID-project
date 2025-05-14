from datetime import datetime
from app import db
from flask_login import UserMixin
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import Text, Boolean
import os

# Check if we're using PostgreSQL
is_postgresql = 'postgresql' in os.environ.get('DATABASE_URL', '')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    dids = db.relationship('DID', backref='user', lazy=True, cascade="all, delete-orphan")
    credentials = db.relationship('Credential', backref='user', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<User {self.username}>'

class DID(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    did_id = db.Column(db.String(255), unique=True, nullable=False)
    method = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)  # This should be encrypted in production
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    active = db.Column(db.Boolean, default=True)
    blockchain_tx_hash = db.Column(db.String(66), nullable=True)  # Ethereum transaction hash
    
    # Store the complete DID document as JSON
    document = db.Column(JSONB if is_postgresql else Text, nullable=False)
    
    def __repr__(self):
        return f'<DID {self.did_id}>'

class Credential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    credential_id = db.Column(db.String(255), unique=True, nullable=False)
    issuer_did = db.Column(db.String(255), nullable=False)
    holder_did = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(100), nullable=False)
    issuance_date = db.Column(db.DateTime, default=datetime.utcnow)
    expiration_date = db.Column(db.DateTime, nullable=True)
    revoked = db.Column(db.Boolean, default=False)
    revocation_date = db.Column(db.DateTime, nullable=True)
    blockchain_proof = db.Column(db.String(66), nullable=True)  # Ethereum transaction hash
    
    # Store the complete credential data as JSON
    credential_data = db.Column(JSONB if is_postgresql else Text, nullable=False)
    
    def __repr__(self):
        return f'<Credential {self.credential_id}>'

class VerificationRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.String(255), unique=True, nullable=False)
    requester_did = db.Column(db.String(255), nullable=False)
    subject_did = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    requested_data = db.Column(JSONB if is_postgresql else Text, nullable=False)
    request_date = db.Column(db.DateTime, default=datetime.utcnow)
    response_date = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    disclosed_data = db.Column(JSONB if is_postgresql else Text, nullable=True)
    
    def __repr__(self):
        return f'<VerificationRequest {self.request_id}>'

class Revocation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    credential_id = db.Column(db.String(255), nullable=False)
    issuer_did = db.Column(db.String(255), nullable=False)
    revocation_date = db.Column(db.DateTime, default=datetime.utcnow)
    reason = db.Column(db.Text, nullable=True)
    blockchain_tx_hash = db.Column(db.String(66), nullable=True)  # Ethereum transaction hash
    
    def __repr__(self):
        return f'<Revocation {self.credential_id}>'
