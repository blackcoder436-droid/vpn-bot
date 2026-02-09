// ========================================
// Burmese Digital Store - Website JS
// ========================================

document.addEventListener('DOMContentLoaded', () => {
    // Navbar scroll effect
    const navbar = document.querySelector('.navbar');
    window.addEventListener('scroll', () => {
        navbar.classList.toggle('scrolled', window.scrollY > 50);
    });

    // Mobile menu toggle
    const mobileToggle = document.querySelector('.mobile-toggle');
    const navLinks = document.querySelector('.nav-links');
    if (mobileToggle) {
        mobileToggle.addEventListener('click', () => {
            navLinks.classList.toggle('active');
            const isOpen = navLinks.classList.contains('active');
            mobileToggle.textContent = isOpen ? '✕' : '☰';
            // Prevent body scroll when menu is open
            document.body.style.overflow = isOpen ? 'hidden' : '';
        });

        // Close mobile menu on link click
        navLinks.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', () => {
                navLinks.classList.remove('active');
                mobileToggle.textContent = '☰';
                document.body.style.overflow = '';
            });
        });

        // Close menu on outside touch/click
        document.addEventListener('click', (e) => {
            if (navLinks.classList.contains('active') 
                && !navLinks.contains(e.target) 
                && !mobileToggle.contains(e.target)) {
                navLinks.classList.remove('active');
                mobileToggle.textContent = '☰';
                document.body.style.overflow = '';
            }
        });
    }

    // Intersection Observer for fade-in animations
    const observerOptions = { threshold: 0.1, rootMargin: '0px 0px -50px 0px' };
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            }
        });
    }, observerOptions);

    document.querySelectorAll('.fade-in').forEach(el => observer.observe(el));

    // FAQ accordion
    document.querySelectorAll('.faq-question').forEach(question => {
        question.addEventListener('click', () => {
            const item = question.parentElement;
            const wasActive = item.classList.contains('active');
            
            // Close all FAQ items
            document.querySelectorAll('.faq-item').forEach(faq => {
                faq.classList.remove('active');
            });

            // Open clicked one (if it wasn't already open)
            if (!wasActive) {
                item.classList.add('active');
            }
        });
    });

    // Pricing tabs
    document.querySelectorAll('.pricing-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const device = tab.dataset.device;
            
            document.querySelectorAll('.pricing-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            document.querySelectorAll('.pricing-card').forEach(card => {
                if (card.dataset.device === device) {
                    card.style.display = 'flex';
                    card.style.animation = 'fadeInUp 0.4s ease forwards';
                } else {
                    card.style.display = 'none';
                }
            });
        });
    });

    // App Store tabs (Play Store / App Store)
    document.querySelectorAll('.app-store-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const store = tab.dataset.store;

            // Update active tab
            document.querySelectorAll('.app-store-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            // Show/hide app grids
            document.querySelectorAll('.app-cards-grid').forEach(grid => {
                if (grid.dataset.store === store) {
                    grid.style.display = 'grid';
                    grid.style.animation = 'fadeInUp 0.4s ease forwards';
                } else {
                    grid.style.display = 'none';
                }
            });
        });
    });

    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                const offset = 80;
                const position = target.offsetTop - offset;
                window.scrollTo({ top: position, behavior: 'smooth' });
            }
        });
    });

    // Active nav link on scroll
    const sections = document.querySelectorAll('section[id]');
    window.addEventListener('scroll', () => {
        const scrollY = window.scrollY + 100;
        sections.forEach(section => {
            const top = section.offsetTop;
            const height = section.offsetHeight;
            const id = section.getAttribute('id');
            const link = document.querySelector(`.nav-links a[href="#${id}"]`);
            if (link) {
                if (scrollY >= top && scrollY < top + height) {
                    document.querySelectorAll('.nav-links a').forEach(l => l.classList.remove('active'));
                    link.classList.add('active');
                }
            }
        });
    });

    // Counter animation
    const animateCounters = () => {
        document.querySelectorAll('.counter').forEach(counter => {
            const target = parseInt(counter.dataset.target);
            const suffix = counter.dataset.suffix || '';
            const duration = 2000;
            const start = 0;
            const startTime = performance.now();

            const updateCounter = (currentTime) => {
                const elapsed = currentTime - startTime;
                const progress = Math.min(elapsed / duration, 1);
                const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
                const current = Math.floor(start + (target - start) * eased);
                counter.textContent = current.toLocaleString() + suffix;

                if (progress < 1) {
                    requestAnimationFrame(updateCounter);
                }
            };

            requestAnimationFrame(updateCounter);
        });
    };

    // Trigger counter animation when hero stats are visible
    const statsObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                animateCounters();
                statsObserver.unobserve(entry.target);
            }
        });
    }, { threshold: 0.5 });

    const heroStats = document.querySelector('.hero-stats');
    if (heroStats) statsObserver.observe(heroStats);

    // Server status ping animation
    const serverCards = document.querySelectorAll('.server-card');
    serverCards.forEach((card, index) => {
        setTimeout(() => {
            card.style.animation = 'fadeInUp 0.5s ease forwards';
        }, index * 100);
    });
});

// fadeInUp keyframes (added via JS for dynamic elements)
const style = document.createElement('style');
style.textContent = `
    @keyframes fadeInUp {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }
`;
document.head.appendChild(style);
