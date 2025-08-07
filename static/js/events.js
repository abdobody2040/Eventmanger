// Events JavaScript for PharmaEvents

document.addEventListener('DOMContentLoaded', function() {
    // Initialize search functionality
    const searchForm = document.getElementById('search_form');
    if (searchForm) {
        searchForm.addEventListener('submit', function(e) {
            e.preventDefault();
            applyFilters();
        });
    }
    
    // Initialize filter change events
    const filterControls = document.querySelectorAll('.filter-control');
    filterControls.forEach(control => {
        control.addEventListener('change', function() {
            applyFilters();
        });
    });
    
    // Initialize event deletion
    const deleteButtons = document.querySelectorAll('.btn-delete-event');
    deleteButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            const eventId = this.getAttribute('data-event-id');
            const eventName = this.getAttribute('data-event-name');
            
            confirmAction(`Are you sure you want to delete event "${eventName}"? This action cannot be undone.`, function() {
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = `/delete-event/${eventId}`;
                document.body.appendChild(form);
                form.submit();
            });
        });
    });
});

// Apply all filters and redirect
function applyFilters() {
    const searchInput = document.getElementById('search_input');
    const categorySelect = document.getElementById('category_filter');
    const typeSelect = document.getElementById('type_filter');
    const dateSelect = document.getElementById('date_filter');
    
    // Build query string
    const params = new URLSearchParams();
    
    if (searchInput && searchInput.value.trim()) {
        params.append('search', searchInput.value.trim());
    }
    
    if (categorySelect && categorySelect.value !== 'all') {
        params.append('category', categorySelect.value);
    }
    
    if (typeSelect && typeSelect.value !== 'all') {
        params.append('type', typeSelect.value);
    }
    
    if (dateSelect && dateSelect.value !== 'all') {
        params.append('date', dateSelect.value);
    }
    
    // Redirect with filters
    window.location.href = `/events?${params.toString()}`;
}

// Function to clear all filters
function clearFilters() {
    // Reset all filter controls
    const searchInput = document.getElementById('search_input');
    if (searchInput) searchInput.value = '';
    
    const filterSelects = document.querySelectorAll('.filter-control');
    filterSelects.forEach(select => {
        select.value = 'all';
    });
    
    // Redirect to events page without params
    window.location.href = '/events';
}

// Toggle card view and list view
function toggleView(viewType) {
    const eventsContainer = document.getElementById('events_container');
    const cardViewBtn = document.getElementById('card_view_btn');
    const listViewBtn = document.getElementById('list_view_btn');
    
    if (viewType === 'card') {
        eventsContainer.classList.remove('list-view');
        eventsContainer.classList.add('card-view');
        cardViewBtn.classList.add('active');
        listViewBtn.classList.remove('active');
        localStorage.setItem('events_view', 'card');
    } else {
        eventsContainer.classList.remove('card-view');
        eventsContainer.classList.add('list-view');
        listViewBtn.classList.add('active');
        cardViewBtn.classList.remove('active');
        localStorage.setItem('events_view', 'list');
    }
}

// Load saved view preference
function loadViewPreference() {
    const savedView = localStorage.getItem('events_view') || 'card';
    toggleView(savedView);
}
