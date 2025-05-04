document.addEventListener('DOMContentLoaded', function() {
    // File upload size validation
    const fileInputs = document.querySelectorAll('input[type="file"]');
    fileInputs.forEach(input => {
        input.addEventListener('change', function() {
            const file = this.files[0];
            if (file) {
                const fileSize = file.size / 1024 / 1024; // in MB
                if (fileSize > 10) { // 10MB limit
                    alert('File size exceeds 10MB limit. Please choose a smaller file.');
                    this.value = '';
                }
            }
        });
    });

    // Password strength indicator
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    passwordInputs.forEach(input => {
        input.addEventListener('input', function() {
            const strengthIndicator = this.nextElementSibling;
            if (strengthIndicator && strengthIndicator.classList.contains('password-strength')) {
                const password = this.value;
                let strength = 0;
                
                // Length check
                if (password.length >= 8) strength++;
                if (password.length >= 12) strength++;
                
                // Complexity checks
                if (/[A-Z]/.test(password)) strength++;
                if (/[0-9]/.test(password)) strength++;
                if (/[^A-Za-z0-9]/.test(password)) strength++;
                
                // Update indicator
                strengthIndicator.textContent = ['Very Weak', 'Weak', 'Moderate', 'Strong', 'Very Strong'][strength];
                strengthIndicator.className = 'password-strength text-xs mt-1 ' + 
                    ['text-red-600', 'text-orange-600', 'text-yellow-600', 'text-blue-600', 'text-green-600'][strength];
            }
        });
    });
});