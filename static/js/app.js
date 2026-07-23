document.addEventListener('DOMContentLoaded', () => {
    console.log('NMAP-X Reconnaissance Platform initialized.');

    // Highlight active route in sidebar
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-link');

    navLinks.forEach(link => {
        const href = link.getAttribute('href');
        if (href === currentPath || (currentPath === '/' && href === '/dashboard')) {
            link.classList.add('active');
        } else {
            link.classList.remove('active');
        }
    });

    // Mobile navigation drawer toggle
    const toggleBtn = document.getElementById('mobile-menu-toggle');
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebar-overlay');

    if (toggleBtn && sidebar && overlay) {
        const toggleMenu = () => {
            sidebar.classList.toggle('open');
            overlay.classList.toggle('active');
        };

        toggleBtn.addEventListener('click', toggleMenu);
        overlay.addEventListener('click', toggleMenu);

        // Close mobile drawer when a nav link is clicked
        navLinks.forEach(link => {
            link.addEventListener('click', () => {
                if (sidebar.classList.contains('open')) {
                    sidebar.classList.remove('open');
                    overlay.classList.remove('active');
                }
            });
        });
    }

    // Update real-time uptime clock on navbar
    const timeDisplay = document.getElementById('navbar-time');
    if (timeDisplay) {
        const updateTime = () => {
            const now = new Date();
            timeDisplay.textContent = now.toUTCString().replace('GMT', 'UTC');
        };
        updateTime();
        setInterval(updateTime, 1000);
    }
});
