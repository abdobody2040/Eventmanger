// Performance optimized loading overlay
document.addEventListener('DOMContentLoaded', function() {
    // Hide loading overlay faster
    const loadingOverlay = document.getElementById('loading_overlay');
    if (loadingOverlay) {
        loadingOverlay.style.display = 'none';
    }

    // Optimize page transitions
    const navLinks = document.querySelectorAll('a.nav-link');
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            // Show loading for navigation only if it's a different page
            if (this.href !== window.location.href) {
                if (loadingOverlay) {
                    loadingOverlay.style.display = 'flex';
                }
            }
        });
    });

    // Hide loading on back/forward navigation
    window.addEventListener('pageshow', function() {
        if (loadingOverlay) {
            loadingOverlay.style.display = 'none';
        }
    });
});