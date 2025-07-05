// Main JavaScript for DID Management System

document.addEventListener('DOMContentLoaded', function() {
    // Toggle password visibility in forms
    const togglePasswordBtns = document.querySelectorAll('.toggle-password');
    togglePasswordBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const input = document.querySelector(this.getAttribute('data-target'));
            if (input.type === 'password') {
                input.type = 'text';
                this.innerHTML = '<i class="bi bi-eye-slash"></i>';
            } else {
                input.type = 'password';
                this.innerHTML = '<i class="bi bi-eye"></i>';
            }
        });
    });

    // Copy to clipboard functionality
    const copyBtns = document.querySelectorAll('.copy-to-clipboard');
    copyBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const textToCopy = document.querySelector(this.getAttribute('data-target')).innerText;
            navigator.clipboard.writeText(textToCopy).then(() => {
                // Change button text temporarily
                const originalText = this.innerHTML;
                this.innerHTML = '<i class="bi bi-check"></i> Copied!';
                setTimeout(() => {
                    this.innerHTML = originalText;
                }, 2000);
            }).catch(err => {
                console.error('Could not copy text: ', err);
            });
        });
    });

    // Credential type selector in issue credential form
    const credentialTypeSelect = document.querySelector('#credential-type-select');
    if (credentialTypeSelect) {
        credentialTypeSelect.addEventListener('change', function() {
            const selectedType = this.value;
            if (!selectedType) return;

            // Show loading indicator
            const attributesContainer = document.querySelector('#credential-attributes');
            attributesContainer.innerHTML = '<div class="spinner-container"><div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div></div>';

            // Fetch schema for selected credential type
            fetch(`/api/credential-type/${selectedType}`)
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Failed to fetch credential type schema');
                    }
                    return response.json();
                })
                .then(typeSchema => {
                    // Generate form fields for attributes
                    attributesContainer.innerHTML = '';
                    
                    if (typeSchema.attributes && typeSchema.attributes.length > 0) {
                        const formGroupTemplate = document.createElement('template');
                        formGroupTemplate.innerHTML = `
                            <div class="mb-3">
                                <label for="attr-{name}" class="form-label">{label}</label>
                                <input type="text" class="form-control" id="attr-{name}" name="{name}" required>
                                <div class="form-text">{description}</div>
                            </div>
                        `;

                        typeSchema.attributes.forEach(attr => {
                            // Convert attribute name to label format (e.g., degreeName -> Degree Name)
                            const label = attr.replace(/([A-Z])/g, ' $1')
                                .replace(/^./, str => str.toUpperCase())
                                .replace(/([a-z])([A-Z])/g, '$1 $2');
                            
                            // Create form group for this attribute
                            const formGroup = formGroupTemplate.content.cloneNode(true);
                            formGroup.querySelector('label').innerText = label;
                            formGroup.querySelector('input').id = `attr-${attr}`;
                            formGroup.querySelector('input').name = attr;
                            formGroup.querySelector('.form-text').innerText = `Enter the ${label.toLowerCase()}`;
                            
                            attributesContainer.appendChild(formGroup);
                        });
                    } else {
                        attributesContainer.innerHTML = '<div class="alert alert-info">No attributes defined for this credential type</div>';
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    attributesContainer.innerHTML = `<div class="alert alert-danger">Error loading credential type: ${error.message}</div>`;
                });
        });
    }

    // Form validation
    const forms = document.querySelectorAll('.needs-validation');
    Array.from(forms).forEach(form => {
        form.addEventListener('submit', event => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    });

    // Initialize tooltips
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));

    // Handle credential verification form
    const verifyForm = document.querySelector('#verify-credential-form');
    if (verifyForm) {
        // Add JSON formatter for easier input
        const jsonInput = document.querySelector('#credential-json');
        if (jsonInput) {
            jsonInput.addEventListener('blur', function() {
                try {
                    // Try to parse and format the JSON
                    const json = JSON.parse(this.value);
                    this.value = JSON.stringify(json, null, 2);
                    // Remove any error styling
                    this.classList.remove('is-invalid');
                } catch (e) {
                    // If not valid JSON, add error styling
                    if (this.value.trim() !== '') {
                        this.classList.add('is-invalid');
                    }
                }
            });
        }
    }

    // DID selection for credential operations
    const issuerDidSelect = document.querySelector('#issuer-did');
    if (issuerDidSelect) {
        // When an issuer DID is selected, show its verification methods
        issuerDidSelect.addEventListener('change', function() {
            const selectedDid = this.value;
            // In a real implementation, we would fetch the DID document and display verification methods
            // For now, this is a placeholder
            console.log('Selected issuer DID:', selectedDid);
        });
    }

    // Revocation modal
    const revokeModal = document.getElementById('revokeCredentialModal');
    if (revokeModal) {
        revokeModal.addEventListener('show.bs.modal', function (event) {
            // Button that triggered the modal
            const button = event.relatedTarget;
            // Extract credential info from data attributes
            const credentialId = button.getAttribute('data-credential-id');
            const credentialType = button.getAttribute('data-credential-type');
            
            // Update the modal content
            const modalTitle = revokeModal.querySelector('.modal-title');
            const credentialIdInput = revokeModal.querySelector('#revoke-credential-id');
            
            modalTitle.textContent = `Revoke ${credentialType} Credential`;
            credentialIdInput.value = credentialId;
        });
    }
});                        
