// Create Event JavaScript for PharmaEvents

document.addEventListener('DOMContentLoaded', function() {
    // We'll use native date/time inputs instead of flatpickr to avoid validation issues

    // Initialize select2 for multi-select
    if (typeof $.fn.select2 !== 'undefined') {
        $('.select2').select2({
            theme: 'bootstrap4',
            width: '100%'
        });
    }

    // File upload preview functionality
    const attendeesFileInput = document.getElementById('attendees_file');
    const filePreview = document.getElementById('file_preview');
    const fileName = document.getElementById('file_name');

    if (attendeesFileInput) {
        attendeesFileInput.addEventListener('change', function() {
            if (this.files && this.files[0]) {
                const file = this.files[0];
                fileName.textContent = file.name;
                filePreview.classList.remove('d-none');
                
                // Validate file type
                const allowedTypes = ['application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'text/csv'];
                const allowedExtensions = ['.xlsx', '.xls', '.csv'];
                const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
                
                if (!allowedExtensions.includes(fileExtension)) {
                    filePreview.className = 'alert alert-danger';
                    fileName.textContent = file.name + ' - Invalid file type! Please upload .xlsx, .xls, or .csv files only.';
                } else {
                    filePreview.className = 'alert alert-info';
                }
            } else {
                filePreview.classList.add('d-none');
            }
        });
    }

    // Venue is now free text, no dropdown handling needed

    // Online event toggle logic
    const onlineCheckbox = document.getElementById('is_online');
    const venueFields = document.getElementById('venue_fields');

    if (onlineCheckbox && venueFields) {
        onlineCheckbox.addEventListener('change', function() {
            if (this.checked) {
                venueFields.classList.add('d-none');
            } else {
                venueFields.classList.remove('d-none');
            }
        });

        // Initial state
        if (onlineCheckbox.checked) {
            venueFields.classList.add('d-none');
        }
    }

    // Auto-calculate registration deadline (2 days after end date)
    const endDateInput = document.getElementById('end_date');
    const endTimeInput = document.getElementById('end_time');
    const regDeadlineDateInput = document.getElementById('registration_deadline_date');
    const regDeadlineTimeInput = document.getElementById('registration_deadline_time');

    function calculateRegistrationDeadline() {
        if (endDateInput.value) {
            const endDate = new Date(endDateInput.value);
            // Add 2 days
            endDate.setDate(endDate.getDate() + 2);
            
            // Format date as YYYY-MM-DD
            const year = endDate.getFullYear();
            const month = String(endDate.getMonth() + 1).padStart(2, '0');
            const day = String(endDate.getDate()).padStart(2, '0');
            const formattedDate = `${year}-${month}-${day}`;
            
            regDeadlineDateInput.value = formattedDate;
            
            // If end time is set, use the same time for registration deadline
            if (endTimeInput.value) {
                regDeadlineTimeInput.value = endTimeInput.value;
            }
        }
    }

    // Listen for changes to end date and time
    if (endDateInput && regDeadlineDateInput) {
        endDateInput.addEventListener('change', calculateRegistrationDeadline);
        endTimeInput.addEventListener('change', function() {
            if (regDeadlineDateInput.value && endTimeInput.value) {
                regDeadlineTimeInput.value = endTimeInput.value;
            }
        });
    }

    // Form validation and submission
    const form = document.getElementById('event_form');
    const submitButton = document.getElementById('submit_event_btn');

    if (form && submitButton) {
        // Listen for form submission
        form.addEventListener('submit', function(event) {
            event.preventDefault();
            
            // Basic validation
            const title = document.getElementById('title').value.trim();
            const description = document.getElementById('description').value.trim();
            const startDate = document.getElementById('start_date').value;
            const startTime = document.getElementById('start_time').value;
            const endDate = document.getElementById('end_date').value;
            const endTime = document.getElementById('end_time').value;
            
            // Check required fields
            if (!title) {
                alert('Event title is required');
                return false;
            }

            if (!startDate || !startTime) {
                alert('Start date and time are required');
                return false;
            }

            if (!endDate || !endTime) {
                alert('End date and time are required');
                return false;
            }

            if (!description) {
                alert('Event description is required');
                return false;
            }

            // Validate dates - convert to ISO format to ensure proper parsing
            try {
                const startDateTime = new Date(`${startDate}T${startTime}:00`);
                const endDateTime = new Date(`${endDate}T${endTime}:00`);
                const now = new Date();

                // Check if dates are valid
                if (isNaN(startDateTime.getTime()) || isNaN(endDateTime.getTime())) {
                    alert('Invalid date or time format. Please use the date/time selectors.');
                    return false;
                }

                // Validation checks
                if (startDateTime < now) {
                    alert('Start date cannot be in the past');
                    return false;
                }

                if (endDateTime < startDateTime) {
                    alert('End date must be after or equal to start date');
                    return false;
                }
            } catch (e) {
                console.error('Date validation error:', e);
                alert('There was a problem with the date format. Please ensure all dates are correctly formatted.');
                return false;
            }

            // Show loading overlay
            const loadingOverlay = document.getElementById('loading_overlay');
            if (loadingOverlay) {
                loadingOverlay.style.display = 'flex';
            }

            // Disable submit button to prevent double submission
            submitButton.disabled = true;
            submitButton.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span> Processing...';

            // Submit the form
            form.submit();
        });
    }
});

// Update venue options based on selected governorate
function updateVenueOptions(governorate) {
    const venueSelect = document.getElementById('venue_id');
    if (!venueSelect) return;

    // Disable select during update
    venueSelect.disabled = true;

    // Get all venue options
    const venueOptions = venueSelect.querySelectorAll('option');

    // Show only venues in the selected governorate
    venueOptions.forEach(option => {
        const venueGovernorate = option.getAttribute('data-governorate');

        if (!venueGovernorate || option.value === '') {
            // Always show the default "Select a venue" option
            option.style.display = '';
        } else if (venueGovernorate === governorate) {
            option.style.display = '';
        } else {
            option.style.display = 'none';
        }
    });

    // Reset selection if current selection is now hidden
    const selectedOption = venueSelect.options[venueSelect.selectedIndex];
    if (selectedOption && selectedOption.style.display === 'none') {
        venueSelect.value = '';
    }

    // Re-enable select
    venueSelect.disabled = false;
}

// Validate the event form
function validateEventForm() {
    let isValid = true;
    const form = document.getElementById('event_form');

    // Reset previous error messages
    const errorMessages = form.querySelectorAll('.error-message');
    errorMessages.forEach(msg => msg.remove());

    // Check required fields
    const requiredFields = form.querySelectorAll('[required]');
    requiredFields.forEach(field => {
        field.classList.remove('is-invalid');

        if (!field.value.trim()) {
            field.classList.add('is-invalid');
            addErrorMessage(field, 'This field is required');
            isValid = false;
        }
    });

    // Get date and time values
    const startDateVal = document.getElementById('start_date').value;
    const startTimeVal = document.getElementById('start_time').value;
    const endDateVal = document.getElementById('end_date').value;
    const endTimeVal = document.getElementById('end_time').value;
    
    // Format for proper parsing
    let startDateObj, endDateObj;
    const now = new Date();
    
    try {
        // Parse date strings properly using local date objects
        // Format: yyyy-mm-dd hh:mm
        startDateObj = new Date(`${startDateVal} ${startTimeVal}`);
        endDateObj = new Date(`${endDateVal} ${endTimeVal}`);
        
        // Debug info to console
        console.log('Start Date:', startDateVal, startTimeVal, startDateObj);
        console.log('End Date:', endDateVal, endTimeVal, endDateObj);
    } catch (e) {
        console.error('Date parsing error:', e);
    }

    // Validate start date
    if (!startDateVal || !startTimeVal || isNaN(startDateObj.getTime())) {
        document.getElementById('start_date').classList.add('is-invalid');
        document.getElementById('start_time').classList.add('is-invalid');
        addErrorMessage(document.getElementById('start_date'), 'Please enter valid start date and time');
        isValid = false;
    }

    // Validate end date
    if (!endDateVal || !endTimeVal || isNaN(endDateObj.getTime())) {
        document.getElementById('end_date').classList.add('is-invalid');
        document.getElementById('end_time').classList.add('is-invalid');
        addErrorMessage(document.getElementById('end_date'), 'Please enter valid end date and time');
        isValid = false;
    }

    // Check date logic only if all dates are valid
    if (isValid) {
        // End date should be equal to or after start date
        if (endDateObj < startDateObj) {
            document.getElementById('end_date').classList.add('is-invalid');
            addErrorMessage(document.getElementById('end_date'), 'End date must be after or equal to start date');
            isValid = false;
        }
    }

    // Check if a category is selected
    const categories = document.getElementById('categories');
    if (categories && !categories.value) {
        categories.classList.add('is-invalid');
        addErrorMessage(categories, 'Please select a category');
        isValid = false;
    }

    // Check venue selection for offline events
    const isOnline = document.getElementById('is_online').checked;
    if (!isOnline) {
        const governorate = document.getElementById('governorate');
        if (!governorate.value) {
            addErrorMessage(governorate, 'Please select a governorate for offline events');
            isValid = false;
        }
    }

    return isValid;
}

// Add error message below a field
function addErrorMessage(field, message) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'invalid-feedback error-message';
    errorDiv.textContent = message;

    field.parentNode.appendChild(errorDiv);
}

// Add additional initialization code when the document is ready
document.addEventListener('DOMContentLoaded', function() {
    // Set min dates to today for all date inputs
    const today = new Date();
    const todayStr = today.toISOString().split('T')[0];
    
    const dateInputs = document.querySelectorAll('input[type="date"]');
    dateInputs.forEach(input => {
        input.min = todayStr;
    });
    
    // Image preview handler for event banner
    const imageInput = document.getElementById('event_banner');
    const imagePreview = document.getElementById('image_preview');
    const imagePreviewContainer = document.getElementById('image_preview_container');
    
    if (imageInput && imagePreview && imagePreviewContainer) {
        imageInput.addEventListener('change', function() {
            const file = this.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = function(e) {
                    imagePreview.src = e.target.result;
                    imagePreviewContainer.classList.remove('d-none');
                };
                reader.readAsDataURL(file);
            }
        });
    }
});