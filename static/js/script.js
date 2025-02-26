let lastScrollTop = 0;
const navbar = document.querySelector('.navbar');

window.addEventListener('scroll', () => {
    requestAnimationFrame(() => {
        const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
        navbar.style.top = (scrollTop > lastScrollTop) ? '-70px' : '0'; // Hide navbar when scrolling down
        lastScrollTop = scrollTop;
    });
});

// Scroll-to-Top Button Functionality
const scrollToTopBtn = document.getElementById('scrollToTopBtn');

window.addEventListener('scroll', () => {
    requestAnimationFrame(() => {
        scrollToTopBtn.style.display = (window.scrollY > 20) ? 'block' : 'none';
    });
});

scrollToTopBtn.addEventListener('click', () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
});