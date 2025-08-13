// Main JavaScript for PharmaEvents Application

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Initialize user dropdown with proper positioning
    const userDropdown = document.getElementById('userMenuDropdown');
    if (userDropdown) {
        const dropdown = new bootstrap.Dropdown(userDropdown, {
            boundary: 'viewport',
            display: 'static'
        });
        
        // Add event listener to ensure proper positioning
        userDropdown.addEventListener('shown.bs.dropdown', function () {
            const dropdownMenu = this.nextElementSibling;
            const rect = this.getBoundingClientRect();
            const viewportWidth = window.innerWidth;
            
            // Ensure dropdown doesn't go off screen on the right
            if (rect.right + dropdownMenu.offsetWidth > viewportWidth) {
                dropdownMenu.style.right = '0';
                dropdownMenu.style.left = 'auto';
                dropdownMenu.style.transform = 'translateX(0)';
            }
        });
    }

    // Custom file input label
    const fileInputs = document.querySelectorAll('.custom-file-input');
    fileInputs.forEach(input => {
        input.addEventListener('change', function(e) {
            const fileName = this.files[0]?.name || 'Choose file';
            const label = this.nextElementSibling;
            label.textContent = fileName;
        });
    });

    // Form validation
    const forms = document.querySelectorAll('.needs-validation');
    forms.forEach(form => {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    });

    // Toggle online/offline event fields
    const onlineCheckbox = document.getElementById('is_online');
    if (onlineCheckbox) {
        const venueFields = document.getElementById('venue_fields');
        
        // Initial state
        toggleVenueFields();
        
        // Add change listener
        onlineCheckbox.addEventListener('change', toggleVenueFields);
        
        function toggleVenueFields() {
            if (onlineCheckbox.checked) {
                venueFields.classList.add('d-none');
            } else {
                venueFields.classList.remove('d-none');
            }
        }
    }

    // Handle flash messages auto-close
    const alerts = document.querySelectorAll('.alert:not(.alert-dismissible)');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.classList.add('fade');
            setTimeout(() => {
                alert.remove();
            }, 500);
        }, 5000);
    });

    // Handle deletion confirmations
    const deleteButtons = document.querySelectorAll('.btn-delete-item');
    deleteButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            if (!confirm('Are you sure you want to delete this item? This action cannot be undone.')) {
                e.preventDefault();
            }
        });
    });

    // Handle image URL / file upload toggle
    const imageUrlRadio = document.getElementById('image_url_option');
    const fileUploadRadio = document.getElementById('file_upload_option');
    
    if (imageUrlRadio && fileUploadRadio) {
        const imageUrlField = document.getElementById('image_url_field');
        const fileUploadField = document.getElementById('file_upload_field');
        
        imageUrlRadio.addEventListener('change', toggleImageFields);
        fileUploadRadio.addEventListener('change', toggleImageFields);
        
        // Initial state
        toggleImageFields();
        
        function toggleImageFields() {
            if (imageUrlRadio.checked) {
                imageUrlField.classList.remove('d-none');
                fileUploadField.classList.add('d-none');
            } else {
                imageUrlField.classList.add('d-none');
                fileUploadField.classList.remove('d-none');
            }
        }
    }

    // Preview uploaded image
    const eventBannerInput = document.getElementById('event_banner');
    const previewContainer = document.getElementById('image_preview_container');
    const previewImage = document.getElementById('image_preview');
    
    if (eventBannerInput && previewContainer && previewImage) {
        eventBannerInput.addEventListener('change', function() {
            const file = this.files[0];
            if (file) {
                const reader = new FileReader();
                
                reader.addEventListener('load', function() {
                    previewImage.src = reader.result;
                    previewContainer.classList.remove('d-none');
                });
                
                reader.readAsDataURL(file);
            } else {
                previewContainer.classList.add('d-none');
            }
        });
    }
});

// Show loading overlay during form submissions
function showLoading() {
    const loadingOverlay = document.getElementById('loading_overlay');
    if (loadingOverlay) {
        loadingOverlay.style.display = 'flex';
    }
}

// Date/time formatting helper
function formatDateTime(dateTimeStr) {
    const date = new Date(dateTimeStr);
    return date.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Function to show confirmation dialog
function confirmAction(message, callback) {
    if (confirm(message)) {
        callback();
    }
}

// Function to format a date object to YYYY-MM-DD for inputs
function formatDateForInput(date) {
    return date.toISOString().split('T')[0];
}

// Function to format a date object to HH:MM for inputs
function formatTimeForInput(date) {
    return date.toTimeString().substring(0, 5);
}
