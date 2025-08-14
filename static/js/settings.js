document.addEventListener('DOMContentLoaded', function() {
    // Utility function to show alerts
    function showAlert(message, type = 'info') {
        const alertsContainer = document.querySelector('.container-fluid');
        const alert = document.createElement('div');
        alert.className = `alert alert-${type} alert-dismissible fade show`;
        alert.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        alertsContainer.insertBefore(alert, alertsContainer.firstChild);

        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            if (alert.parentNode) {
                alert.remove();
            }
        }, 5000);
    }

    // Theme color picker
    const themeColorInput = document.getElementById('theme_color');
    const presetColors = document.querySelectorAll('.preset-color');

    if (themeColorInput) {
        themeColorInput.addEventListener('change', function() {
            updateThemeColor(this.value);
        });
    }

    if (presetColors) {
        presetColors.forEach(colorBtn => {
            colorBtn.addEventListener('click', function() {
                const color = this.getAttribute('data-color');
                if (themeColorInput) {
                    themeColorInput.value = color;
                }
                updateThemeColor(color);
            });
        });
    }

    function updateThemeColor(color) {
        fetch('/api/settings/theme', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'same-origin',
            body: JSON.stringify({ theme_color: color })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Apply theme immediately
                document.documentElement.style.setProperty('--primary', color);
                showAlert('Theme color updated successfully!', 'success');
            } else {
                console.error('Theme update error:', data);
                showAlert(data.error || 'Error updating theme color', 'danger');
            }
        })
        .catch(error => {
            console.error('Error updating theme color:', error);
            showAlert('Error updating theme color', 'danger');
        });
    }

    // App name update
    const appNameInput = document.getElementById('app_name');
    const updateAppBtn = document.getElementById('update_app_name');

    if (appNameInput && updateAppBtn) {
        updateAppBtn.addEventListener('click', function() {
            const appName = appNameInput.value.trim();
            if (!appName) {
                showAlert('App name cannot be empty', 'warning');
                return;
            }

            fetch('/api/settings/app', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'same-origin',
                body: JSON.stringify({ name: appName })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAlert('App name updated successfully! Refreshing page...', 'success');
                    setTimeout(() => location.reload(), 1500);
                } else {
                    showAlert(data.error || 'Error updating app name', 'danger');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showAlert('Error updating app name', 'danger');
            });
        });
    }

    // Logo upload
    const logoInput = document.getElementById('app_logo');
    const uploadLogoBtn = document.getElementById('upload_logo');

    if (logoInput && uploadLogoBtn) {
        uploadLogoBtn.addEventListener('click', function() {
            const file = logoInput.files[0];
            if (!file) {
                showAlert('Please select a file first', 'warning');
                return;
            }

            // Validate file type
            const allowedTypes = ['image/png', 'image/jpeg', 'image/jpg', 'image/svg+xml'];
            if (!allowedTypes.includes(file.type)) {
                showAlert('Please select a PNG, JPG, or SVG file', 'danger');
                return;
            }

            // Validate file size (2MB max)
            if (file.size > 2 * 1024 * 1024) {
                showAlert('File size must be less than 2MB', 'danger');
                return;
            }

            const formData = new FormData();
            formData.append('logo', file);

            fetch('/api/settings/logo', {
                method: 'POST',
                credentials: 'same-origin',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAlert('Logo updated successfully! Refreshing page...', 'success');
                    setTimeout(() => location.reload(), 1500);
                } else {
                    showAlert(data.error || 'Error updating logo', 'danger');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showAlert('Error updating logo', 'danger');
            });
        });
    }

    // Logo removal
    const removeLogoBtn = document.getElementById('remove_logo');
    if (removeLogoBtn) {
        removeLogoBtn.addEventListener('click', function() {
            if (confirm('Are you sure you want to remove the current logo? This action cannot be undone.')) {
                fetch('/api/settings/logo', {
                    method: 'DELETE',
                    credentials: 'same-origin'
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        showAlert('Logo removed successfully! Refreshing page...', 'success');
                        setTimeout(() => location.reload(), 1500);
                    } else {
                        showAlert(data.error || 'Error removing logo', 'danger');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    showAlert('Error removing logo', 'danger');
                });
            }
        });
    }

    // Login content update
    const updateLoginContentBtn = document.getElementById('update_login_content');
    if (updateLoginContentBtn) {
        updateLoginContentBtn.addEventListener('click', function() {
            const loginContentData = {
                main_tagline: document.getElementById('main_tagline')?.value || '',
                main_header: document.getElementById('main_header')?.value || '',
                app_description: document.getElementById('app_description')?.value || '',
                feature1_title: document.getElementById('feature1_title')?.value || '',
                feature1_description: document.getElementById('feature1_description')?.value || '',
                feature2_title: document.getElementById('feature2_title')?.value || '',
                feature2_description: document.getElementById('feature2_description')?.value || ''
            };

            fetch('/api/settings/login-content', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'same-origin',
                body: JSON.stringify(loginContentData)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAlert('Login content updated successfully!', 'success');
                } else {
                    showAlert(data.error || 'Error updating login content', 'danger');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showAlert('Error updating login content', 'danger');
            });
        });
    }

    // Category management
    const addCategoryForm = document.getElementById('add_category_form');
    if (addCategoryForm) {
        addCategoryForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const categoryName = document.getElementById('category_name').value;

            const formData = new FormData();
            formData.append('category_name', categoryName);

            fetch('/api/categories', {
                method: 'POST',
                credentials: 'same-origin',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAlert('Category added successfully!', 'success');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showAlert(data.error || 'Error adding category', 'danger');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showAlert('Error adding category', 'danger');
            });
        });
    }

    // Event Type management
    const addEventTypeForm = document.getElementById('add_type_form');
    if (addEventTypeForm) {
        addEventTypeForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const typeName = document.getElementById('type_name').value;

            const formData = new FormData();
            formData.append('type_name', typeName);

            fetch('/api/event-types', {
                method: 'POST',
                credentials: 'same-origin',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAlert('Event type added successfully!', 'success');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showAlert(data.error || 'Error adding event type', 'danger');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showAlert('Error adding event type', 'danger');
            });
        });
    }

    // Delete category buttons
    const deleteCategoryBtns = document.querySelectorAll('.btn-delete-category');
    deleteCategoryBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const categoryId = this.getAttribute('data-id');
            const categoryName = this.getAttribute('data-name');
            if (confirm(`Are you sure you want to delete category "${categoryName}"?`)) {
                fetch(`/api/categories/${categoryId}`, {
                    method: 'DELETE',
                    credentials: 'same-origin'
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        showAlert('Category deleted successfully!', 'success');
                        setTimeout(() => location.reload(), 1000);
                    } else {
                        showAlert(data.error || 'Error deleting category', 'danger');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    showAlert('Error deleting category', 'danger');
                });
            }
        });
    });

    // Delete event type buttons
    const deleteEventTypeBtns = document.querySelectorAll('.btn-delete-type');
    deleteEventTypeBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const typeId = this.getAttribute('data-id');
            const typeName = this.getAttribute('data-name');
            if (confirm(`Are you sure you want to delete event type "${typeName}"?`)) {
                fetch(`/api/event-types/${typeId}`, {
                    method: 'DELETE',
                    credentials: 'same-origin'
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        showAlert('Event type deleted successfully!', 'success');
                        setTimeout(() => location.reload(), 1000);
                    } else {
                        showAlert(data.error || 'Error deleting event type', 'danger');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    showAlert('Error deleting event type', 'danger');
                });
            }
        });
    });

    // User management
    const addUserForm = document.getElementById('add_user_form');
    if (addUserForm) {
        addUserForm.addEventListener('submit', function(e) {
            e.preventDefault();

            const email = document.getElementById('user_email').value;
            const password = document.getElementById('user_password').value;
            const role = document.getElementById('user_role').value;

            const formData = new FormData();
            formData.append('email', email);
            formData.append('password', password);
            formData.append('role', role);

            fetch('/api/users', {
                method: 'POST',
                credentials: 'same-origin',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAlert('User added successfully!', 'success');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showAlert(data.error || 'Error adding user', 'danger');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showAlert('Error adding user', 'danger');
            });
        });
    }

    // Delete user buttons
    const deleteUserBtns = document.querySelectorAll('.btn-delete-user');
    deleteUserBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const userId = this.getAttribute('data-id');
            if (confirm('Are you sure you want to delete this user?')) {
                fetch(`/api/users/${userId}`, {
                    method: 'DELETE',
                    credentials: 'same-origin'
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        showAlert('User deleted successfully!', 'success');
                        setTimeout(() => location.reload(), 1000);
                    } else {
                        showAlert(data.error || 'Error deleting user', 'danger');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    showAlert('Error deleting user', 'danger');
                });
            }
        });
    });

    // API Token Management
    const createTokenForm = document.getElementById('create_token_form');
    if (createTokenForm) {
        createTokenForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const tokenName = document.getElementById('token_name').value.trim();
            
            if (!tokenName) {
                showAlert('Please enter a token name', 'warning');
                return;
            }
            
            fetch('/api/tokens', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'same-origin',
                body: JSON.stringify({ name: tokenName })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('new_token_value').value = data.token;
                    const modal = new bootstrap.Modal(document.getElementById('tokenModal'));
                    modal.show();
                    document.getElementById('token_name').value = '';
                    loadTokens();
                } else {
                    showAlert(data.error || 'Error creating token', 'danger');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showAlert('Error creating token', 'danger');
            });
        });
    }

    // Load tokens function
    function loadTokens() {
        // Only load tokens if the tokens list element exists
        const tokensList = document.getElementById('tokens_list');
        if (!tokensList) {
            return; // Exit early if tokens section doesn't exist
        }
        
        fetch('/api/tokens', {
            method: 'GET',
            credentials: 'same-origin'
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            const tokensList = document.getElementById('tokens_list');
            if (data.tokens && data.tokens.length > 0) {
                let html = '<div class="table-responsive"><table class="table table-sm">';
                html += '<thead><tr><th>Name</th><th>Created</th><th>Last Used</th><th>Actions</th></tr></thead><tbody>';
                
                data.tokens.forEach(token => {
                    const createdDate = new Date(token.created_at).toLocaleDateString();
                    const lastUsed = token.last_used ? new Date(token.last_used).toLocaleDateString() : 'Never';
                    
                    html += `<tr>
                        <td>${token.name}</td>
                        <td>${createdDate}</td>
                        <td>${lastUsed}</td>
                        <td>
                            <button class="btn btn-sm btn-danger" onclick="deleteToken(${token.id}, '${token.name}')">Delete</button>
                        </td>
                    </tr>`;
                });
                
                html += '</tbody></table></div>';
                tokensList.innerHTML = html;
            } else {
                tokensList.innerHTML = '<p class="text-muted">No active tokens found.</p>';
            }
        })
        .catch(error => {
            console.error('Error loading tokens:', error);
            // Only show user-facing error if this was an intentional load
            const tokensList = document.getElementById('tokens_list');
            if (tokensList) {
                tokensList.innerHTML = '<div class="text-muted">API tokens not available</div>';
            }
        });
    }

    // Load tokens on page load only if the tokens section exists
    if (document.getElementById('tokens_list')) {
        loadTokens();
    }

    // Copy token function
    window.copyToken = function() {
        const tokenInput = document.getElementById('new_token_value');
        tokenInput.select();
        document.execCommand('copy');
        showAlert('Token copied to clipboard!', 'success');
    };

    // Delete token function
    window.deleteToken = function(tokenId, tokenName) {
        if (confirm(`Are you sure you want to delete the token "${tokenName}"? This action cannot be undone.`)) {
            fetch(`/api/tokens/${tokenId}`, {
                method: 'DELETE',
                credentials: 'same-origin'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAlert('Token deleted successfully!', 'success');
                    loadTokens();
                } else {
                    showAlert(data.error || 'Error deleting token', 'danger');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showAlert('Error deleting token', 'danger');
            });
        }
    };

    // Database backup functionality
    const backupButton = document.getElementById('backup_database');
    if (backupButton) {
        backupButton.addEventListener('click', function() {
            const button = this;
            const originalText = button.innerHTML;
            
            // Show loading state
            button.disabled = true;
            button.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i> Creating Backup...';
            
            fetch('/api/database/backup', {
                method: 'POST',
                credentials: 'same-origin'
            })
            .then(response => {
                if (response.ok) {
                    // Get the filename from the response headers or use a default
                    const filename = response.headers.get('Content-Disposition')?.match(/filename="(.+)"/)?.[1] || 'database_backup.sql';
                    return response.blob().then(blob => ({ blob, filename }));
                } else {
                    return response.json().then(data => Promise.reject(data));
                }
            })
            .then(({ blob, filename }) => {
                // Create download link
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
                
                showAlert('Database backup downloaded successfully!', 'success');
            })
            .catch(error => {
                console.error('Error:', error);
                showAlert(error.error || 'Error creating database backup', 'danger');
            })
            .finally(() => {
                // Restore button state
                button.disabled = false;
                button.innerHTML = originalText;
            });
        });
    }

    // Database restore functionality
    const restoreButton = document.getElementById('restore_database');
    if (restoreButton) {
        restoreButton.addEventListener('click', function() {
            const fileInput = document.getElementById('restore_file');
            const file = fileInput.files[0];
            
            if (!file) {
                showAlert('Please select a backup file first', 'warning');
                return;
            }
            
            // Validate file type
            if (!file.name.endsWith('.sql')) {
                showAlert('Please select a valid SQL backup file', 'danger');
                return;
            }
            
            // Confirm the destructive action
            if (!confirm('This will permanently replace ALL current data with the backup. Are you absolutely sure you want to continue?')) {
                return;
            }
            
            const button = this;
            const originalText = button.innerHTML;
            
            // Show loading state
            button.disabled = true;
            button.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i> Restoring...';
            
            const formData = new FormData();
            formData.append('backup_file', file);
            
            fetch('/api/database/restore', {
                method: 'POST',
                credentials: 'same-origin',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAlert('Database restored successfully! The page will refresh...', 'success');
                    setTimeout(() => location.reload(), 2000);
                } else {
                    showAlert(data.error || 'Error restoring database', 'danger');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showAlert('Error restoring database', 'danger');
            })
            .finally(() => {
                // Restore button state
                button.disabled = false;
                button.innerHTML = originalText;
                fileInput.value = ''; // Clear the file input
            });
        });
    }
});