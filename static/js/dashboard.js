// Dashboard JavaScript for PharmaEvents

document.addEventListener('DOMContentLoaded', function() {
    // Check if Chart.js is available
    if (typeof Chart === 'undefined') {
        console.warn('Chart.js is not loaded');
        return;
    }

    // Load dashboard data
    loadDashboardData();

    // Initialize charts
    initializeCharts();
});

async function loadDashboardData() {
    try {
        const response = await fetch('/api/dashboard/stats');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        updateDashboardStats(data);
    } catch (error) {
        console.error('Error loading dashboard data:', error);
        // Show fallback data
        updateDashboardStats({
            total_events: 0,
            upcoming_events: 0,
            active_users: 0
        });
    }
}

function updateDashboardStats(data) {
    // Update stat cards
    const totalEvents = document.getElementById('total_events');
    const upcomingEvents = document.getElementById('upcoming_events');
    const activeUsers = document.getElementById('active_users');

    if (totalEvents) totalEvents.textContent = data.total_events || 0;
    if (upcomingEvents) upcomingEvents.textContent = data.upcoming_events || 0;
    if (activeUsers) activeUsers.textContent = data.active_users || 0;
}

async function initializeCharts() {
    if (typeof Chart === 'undefined') {
        console.warn('Chart.js is not available, skipping chart initialization');
        return;
    }

    try {
        const response = await fetch('/api/dashboard/charts');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        createEventsByMonthChart(data.events_by_month || []);
        createEventsByCategoryChart(data.events_by_category || []);
    } catch (error) {
        console.error('Error loading chart data:', error);
        // Initialize empty charts
        createEventsByMonthChart([]);
        createEventsByCategoryChart([]);
    }
}

function createEventsByMonthChart(data) {
    const ctx = document.getElementById('eventsChart');
    if (!ctx || typeof Chart === 'undefined') return;

    try {
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.length > 0 ? data.map(item => item.month) : ['No Data'],
                datasets: [{
                    label: 'Events',
                    data: data.length > 0 ? data.map(item => item.count) : [0],
                    borderColor: getComputedStyle(document.documentElement).getPropertyValue('--primary') || '#0f6e84',
                    backgroundColor: (getComputedStyle(document.documentElement).getPropertyValue('--primary') || '#0f6e84') + '20',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    } catch (error) {
        console.error('Error creating events chart:', error);
    }
}

function createEventsByCategoryChart(data) {
    const ctx = document.getElementById('categoryChart');
    if (!ctx || typeof Chart === 'undefined') return;

    const colors = [
        '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', 
        '#9966FF', '#FF9F40', '#FF6384', '#C9CBCF'
    ];

    try {
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: data.length > 0 ? data.map(item => item.category) : ['No Data'],
                datasets: [{
                    data: data.length > 0 ? data.map(item => item.count) : [1],
                    backgroundColor: data.length > 0 ? colors.slice(0, data.length) : ['#e9ecef'],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    } catch (error) {
        console.error('Error creating category chart:', error);
    }
}