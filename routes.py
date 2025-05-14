import json
import logging
from datetime import datetime, timedelta
from flask import render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash

from app import app, db
from models import User, DID, Credential
from wallet import DIDWallet
from blockchain import BlockchainIntegration
from auth import Auth
from credentials import CredentialManager
from utils import DIDUtils

logger = logging.getLogger(__name__)

# Home page route
@app.route('/')
def index():
    return render_template('index.html')

# User registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Basic validation
        if not username or not email or not password:
            flash('All fields are required', 'danger')
            return render_template('register.html')
            
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
            
        # Register the user
        user = Auth.register_user(username, email, password)
        
        if user:
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username or email already exists', 'danger')
            
    return render_template('register.html')

# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form.get('username_or_email')
        password = request.form.get('password')
        
        # Authenticate user
        user = Auth.login(username_or_email, password)
        
        if user:
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'danger')
            
    return render_template('login.html')

# User logout
@app.route('/logout')
@login_required
def logout():
    Auth.logout()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

# User dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    # Get user's DIDs
    user_dids = DID.query.filter_by(user_id=current_user.id, active=True).all()
    
    # Get user's credentials
    user_did_ids = [did.did_id for did in user_dids]
    
    # Credentials issued to the user
    received_credentials = []
    if user_did_ids:
        received_credentials = Credential.query.filter(
            Credential.holder_did.in_(user_did_ids),
            Credential.revoked == False
        ).all()
    
    # Credentials issued by the user
    issued_credentials = []
    if user_did_ids:
        issued_credentials = Credential.query.filter(
            Credential.issuer_did.in_(user_did_ids)
        ).all()
    
    return render_template(
        'dashboard.html',
        user=current_user,
        dids=user_dids,
        did_count=len(user_dids),
        received_credentials=received_credentials,
        issued_credentials=issued_credentials
    )

# Wallet management
@app.route('/wallet')
@login_required
def wallet():
    # Get user's DIDs
    user_dids = DID.query.filter_by(user_id=current_user.id).all()
    
    return render_template(
        'wallet.html',
        user_dids=user_dids
    )

# Create a new DID
@app.route('/wallet/create_did', methods=['POST'])
@login_required
def create_did():
    method = request.form.get('method', 'ethr')
    
    try:
        # Create a new DID
        did_document = DIDWallet.create_did(current_user.id, method)
        
        if did_document:
            flash('DID created successfully!', 'success')
            
            # Anchor the DID on blockchain
            blockchain = BlockchainIntegration()
            tx_hash = blockchain.anchor_did_on_chain(did_document['id'], current_user.id)
            
            if tx_hash:
                flash(f'DID anchored on blockchain with transaction hash: {tx_hash}', 'success')
        else:
            flash('Failed to create DID', 'danger')
            
    except Exception as e:
        logger.error(f"Error creating DID: {str(e)}")
        flash(f'Error creating DID: {str(e)}', 'danger')
    
    return redirect(url_for('wallet'))

# View DID details
@app.route('/wallet/did/<did_id>')
@login_required
def view_did(did_id):
    # Verify ownership
    did = DID.query.filter_by(did_id=did_id, user_id=current_user.id).first()
    
    if not did:
        flash('DID not found or you do not have permission to view it', 'danger')
        return redirect(url_for('wallet'))
    
    # Get the DID document
    did_document = json.loads(did.document)
    
    # Format for display
    formatted_document = DIDUtils.format_did_document(did_document)
    
    # Check if it's anchored on blockchain
    blockchain_verification = None
    if did.blockchain_tx_hash:
        blockchain = BlockchainIntegration()
        blockchain_verification = blockchain.verify_did_on_chain(did_id)
    
    return render_template(
        'wallet.html',
        did=did,
        did_document=formatted_document,
        blockchain_verification=blockchain_verification,
        user_dids=DID.query.filter_by(user_id=current_user.id).all()
    )

# Deactivate a DID
@app.route('/wallet/did/<did_id>/deactivate', methods=['POST'])
@login_required
def deactivate_did(did_id):
    if DIDWallet.deactivate_did(did_id, current_user.id):
        flash('DID deactivated successfully', 'success')
    else:
        flash('Failed to deactivate DID', 'danger')
    
    return redirect(url_for('wallet'))

# Credentials management
@app.route('/credentials')
@login_required
def credentials():
    # Get user's DIDs
    user_dids = DID.query.filter_by(user_id=current_user.id, active=True).all()
    
    # Get credentials where user is the holder
    user_did_ids = [did.did_id for did in user_dids]
    received_credentials = []
    
    if user_did_ids:
        received_credentials = CredentialManager.list_user_credentials(current_user.id, as_holder=True)
    
    # Get credentials issued by the user
    issued_credentials = CredentialManager.list_user_credentials(current_user.id, as_holder=False)
    
    # Get available credential types
    credential_types = DIDUtils.get_credential_types()
    
    return render_template(
        'credentials.html',
        user_dids=user_dids,
        received_credentials=received_credentials,
        issued_credentials=issued_credentials,
        credential_types=credential_types
    )

# Issue credential form
@app.route('/credentials/issue', methods=['GET', 'POST'])
@login_required
def issue_credential():
    # Get user's DIDs for issuer selection
    user_dids = DID.query.filter_by(user_id=current_user.id, active=True).all()
    
    if not user_dids:
        flash('You need to create a DID before issuing credentials', 'warning')
        return redirect(url_for('wallet'))
    
    # Get available credential types
    credential_types = DIDUtils.get_credential_types()
    
    if request.method == 'POST':
        issuer_did_id = request.form.get('issuer_did')
        holder_did_id = request.form.get('holder_did')
        credential_type = request.form.get('credential_type')
        expiration_date_str = request.form.get('expiration_date')
        
        # Get the selected credential type
        selected_type = next((t for t in credential_types if t['id'] == credential_type), None)
        
        if not selected_type:
            flash('Invalid credential type', 'danger')
            return redirect(url_for('issue_credential'))
        
        # Collect credential claims from form
        claims = {}
        for attr in selected_type['attributes']:
            claims[attr] = request.form.get(attr, '')
        
        # Parse expiration date if provided
        expiration_date = None
        if expiration_date_str:
            try:
                expiration_date = datetime.strptime(expiration_date_str, '%Y-%m-%d')
            except ValueError:
                flash('Invalid expiration date format', 'danger')
                return redirect(url_for('issue_credential'))
        
        # Issue the credential
        credential = CredentialManager.issue_credential(
            issuer_did=issuer_did_id,
            holder_did=holder_did_id,
            credential_type=credential_type,
            claims=claims,
            expiration_date=expiration_date,
            user_id=current_user.id
        )
        
        if credential:
            flash('Credential issued successfully!', 'success')
            return redirect(url_for('credentials'))
        else:
            flash('Failed to issue credential', 'danger')
    
    return render_template(
        'issue_credential.html',
        user_dids=user_dids,
        credential_types=credential_types
    )

# View credential details
@app.route('/credentials/view/<credential_id>')
@login_required
def view_credential(credential_id):
    # Get the credential
    credential_data = CredentialManager.get_credential(credential_id)
    
    if not credential_data:
        flash('Credential not found', 'danger')
        return redirect(url_for('credentials'))
    
    # Verify the credential
    verification_result = CredentialManager.verify_credential(credential_data)
    
    # Check if user owns either the issuer or holder DID
    user_dids = DID.query.filter_by(user_id=current_user.id).all()
    user_did_ids = [did.did_id for did in user_dids]
    
    issuer_did = credential_data.get('issuer')
    holder_did = credential_data.get('credentialSubject', {}).get('id')
    
    if issuer_did not in user_did_ids and holder_did not in user_did_ids:
        flash('You do not have permission to view this credential', 'danger')
        return redirect(url_for('credentials'))
    
    # Format dates for display
    issuance_date = credential_data.get('issuanceDate')
    expiration_date = credential_data.get('expirationDate')
    
    if issuance_date:
        credential_data['issuanceDate'] = DIDUtils.format_timestamp(issuance_date)
    
    if expiration_date:
        credential_data['expirationDate'] = DIDUtils.format_timestamp(expiration_date)
    
    # Check revocation status
    blockchain = BlockchainIntegration()
    revocation_status = blockchain.check_revocation_status(credential_id)
    
    return render_template(
        'verify_credential.html',
        credential=credential_data,
        verification_result=verification_result,
        revocation_status=revocation_status,
        is_issuer=(issuer_did in user_did_ids),
        is_holder=(holder_did in user_did_ids),
        formatted_credential=DIDUtils.format_did_document(credential_data)
    )

# Verify credential form
@app.route('/credentials/verify', methods=['GET', 'POST'])
@login_required
def verify_credential_form():
    verification_result = None
    credential_data = None
    
    if request.method == 'POST':
        credential_json = request.form.get('credential_json')
        
        try:
            credential_data = json.loads(credential_json)
            verification_result = CredentialManager.verify_credential(credential_data)
            
            if verification_result.get('verified'):
                flash('Credential successfully verified!', 'success')
            else:
                flash(f"Credential verification failed: {verification_result.get('reason')}", 'danger')
                
            # Check revocation status if verification was successful
            if verification_result.get('verified'):
                blockchain = BlockchainIntegration()
                revocation_status = blockchain.check_revocation_status(credential_data.get('id'))
                verification_result['revocation_status'] = revocation_status
                
        except json.JSONDecodeError:
            flash('Invalid JSON format', 'danger')
            verification_result = {'verified': False, 'reason': 'Invalid JSON format'}
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
            verification_result = {'verified': False, 'reason': str(e)}
    
    return render_template(
        'verify_credential.html',
        verification_result=verification_result,
        credential=credential_data,
        formatted_credential=DIDUtils.format_did_document(credential_data) if credential_data else None
    )

# Revoke credential
@app.route('/credentials/<credential_id>/revoke', methods=['POST'])
@login_required
def revoke_credential(credential_id):
    # Get the credential
    credential = Credential.query.filter_by(credential_id=credential_id).first()
    
    if not credential:
        flash('Credential not found', 'danger')
        return redirect(url_for('credentials'))
    
    # Verify the user is the issuer
    did = DID.query.filter_by(did_id=credential.issuer_did, user_id=current_user.id).first()
    
    if not did:
        flash('You do not have permission to revoke this credential', 'danger')
        return redirect(url_for('credentials'))
    
    reason = request.form.get('reason', '')
    
    # Revoke the credential
    if CredentialManager.revoke_credential(credential_id, credential.issuer_did, current_user.id, reason):
        flash('Credential revoked successfully', 'success')
    else:
        flash('Failed to revoke credential', 'danger')
    
    return redirect(url_for('credentials'))

# API endpoint to get credential type schema
@app.route('/api/credential-type/<type_id>')
def credential_type_schema(type_id):
    credential_types = DIDUtils.get_credential_types()
    selected_type = next((t for t in credential_types if t['id'] == type_id), None)
    
    if not selected_type:
        return jsonify({'error': 'Type not found'}), 404
    
    return jsonify(selected_type)

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {str(e)}")
    return render_template('500.html'), 500
