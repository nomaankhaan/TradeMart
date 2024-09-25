// main.js
document.addEventListener('DOMContentLoaded', function() {
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

    // Product quantity buttons
    const quantityInputs = document.querySelectorAll('.quantity-input');
    quantityInputs.forEach(input => {
        const minusBtn = input.previousElementSibling;
        const plusBtn = input.nextElementSibling;

        minusBtn.addEventListener('click', () => updateQuantity(input, -1));
        plusBtn.addEventListener('click', () => updateQuantity(input, 1));
    });

    function updateQuantity(input, change) {
        let value = parseInt(input.value) + change;
        value = Math.max(1, value); // Ensure the minimum value is 1
        input.value = value;
    }

    // Toggle password visibility
    const togglePasswordBtns = document.querySelectorAll('.toggle-password');
    togglePasswordBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const passwordInput = this.previousElementSibling;
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);
            this.textContent = type === 'password' ? 'Show' : 'Hide';
        });
    });
});