// Global app functionality
console.log('NetScaler Config Viewer loaded');

// Modal functions
function showNetScalerLogin() {
    document.getElementById('netscaler-login-modal').style.display = 'block';
}

function showElchiLogin() {
    document.getElementById('elchi-login-modal').style.display = 'block';
}

function closeModal(modalId) {
    document.getElementById(modalId).style.display = 'none';
}

// Close modal when clicking outside
window.onclick = function(event) {
    if (event.target.className === 'modal') {
        event.target.style.display = 'none';
    }
}

// NetScaler login form
document.addEventListener('DOMContentLoaded', function() {
    const nsForm = document.getElementById('netscaler-login-form');
    if (nsForm) {
        nsForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = {
                host: document.getElementById('ns-host').value,
                username: document.getElementById('ns-username').value,
                password: document.getElementById('ns-password').value
            };
            
            const errorDiv = document.getElementById('ns-error');
            errorDiv.style.display = 'none';
            
            try {
                const response = await fetch('/api/netscaler/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(formData)
                });
                
                const data = await response.json();
                
                if (response.ok && data.success) {
                    // Update status
                    document.getElementById('netscaler-status').className = 'status-connected';
                    document.getElementById('netscaler-status').textContent = 'Connected';
                    document.getElementById('netscaler-login-btn').textContent = 'Logout';
                    document.getElementById('netscaler-login-btn').onclick = netscalerLogout;
                    
                    // Close modal
                    closeModal('netscaler-login-modal');
                    
                    // Reload page if needed
                    if (window.location.pathname === '/') {
                        window.location.reload();
                    }
                } else {
                    errorDiv.textContent = data.message || 'Login failed';
                    errorDiv.style.display = 'block';
                }
            } catch (error) {
                errorDiv.textContent = 'Connection error: ' + error.message;
                errorDiv.style.display = 'block';
            }
        });
    }
    
    // ELCHI login form
    const elchiForm = document.getElementById('elchi-login-form');
    if (elchiForm) {
        elchiForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = {
                host: document.getElementById('elchi-host').value,
                username: document.getElementById('elchi-username').value,
                password: document.getElementById('elchi-password').value
            };
            
            const errorDiv = document.getElementById('elchi-error');
            errorDiv.style.display = 'none';
            
            try {
                const response = await fetch('/api/elchi/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(formData)
                });
                
                const data = await response.json();
                
                if (response.ok && data.success) {
                    // Update status
                    document.getElementById('elchi-status').className = 'status-connected';
                    document.getElementById('elchi-status').textContent = 'Connected';
                    document.getElementById('elchi-login-btn').textContent = 'Logout';
                    document.getElementById('elchi-login-btn').onclick = elchiLogout;
                    
                    // Close modal
                    closeModal('elchi-login-modal');
                } else {
                    errorDiv.textContent = data.message || 'Login failed';
                    errorDiv.style.display = 'block';
                }
            } catch (error) {
                errorDiv.textContent = 'Connection error: ' + error.message;
                errorDiv.style.display = 'block';
            }
        });
    }
    
    // Check login status on page load
    checkLoginStatus();
});

async function netscalerLogout() {
    try {
        const response = await fetch('/api/netscaler/logout', {
            method: 'POST'
        });
        
        if (response.ok) {
            document.getElementById('netscaler-status').className = 'status-disconnected';
            document.getElementById('netscaler-status').textContent = 'Disconnected';
            document.getElementById('netscaler-login-btn').textContent = 'Login';
            document.getElementById('netscaler-login-btn').onclick = showNetScalerLogin;
            
            // Reload if on main page
            if (window.location.pathname !== '/') {
                window.location.href = '/';
            }
        }
    } catch (error) {
        console.error('Logout error:', error);
    }
}

async function elchiLogout() {
    try {
        const response = await fetch('/api/elchi/logout', {
            method: 'POST'
        });
        
        if (response.ok) {
            document.getElementById('elchi-status').className = 'status-disconnected';
            document.getElementById('elchi-status').textContent = 'Disconnected';
            document.getElementById('elchi-login-btn').textContent = 'Login';
            document.getElementById('elchi-login-btn').onclick = showElchiLogin;
        }
    } catch (error) {
        console.error('Logout error:', error);
    }
}

async function checkLoginStatus() {
    // Check NetScaler status
    try {
        const nsResponse = await fetch('/api/netscaler/status');
        const nsData = await nsResponse.json();
        
        if (nsData.authenticated) {
            document.getElementById('netscaler-status').className = 'status-connected';
            document.getElementById('netscaler-status').textContent = 'Connected';
            document.getElementById('netscaler-login-btn').textContent = 'Logout';
            document.getElementById('netscaler-login-btn').onclick = netscalerLogout;
        } else {
            document.getElementById('netscaler-status').className = 'status-disconnected';
            document.getElementById('netscaler-status').textContent = 'Disconnected';
            document.getElementById('netscaler-login-btn').textContent = 'Login';
            document.getElementById('netscaler-login-btn').onclick = showNetScalerLogin;
        }
    } catch (error) {
        console.log('NetScaler status check failed');
    }
    
    // Check ELCHI status
    try {
        const elchiResponse = await fetch('/api/elchi/status');
        const elchiData = await elchiResponse.json();
        
        if (elchiData.authenticated) {
            document.getElementById('elchi-status').className = 'status-connected';
            document.getElementById('elchi-status').textContent = 'Connected';
            document.getElementById('elchi-login-btn').textContent = 'Logout';
            document.getElementById('elchi-login-btn').onclick = elchiLogout;
        } else {
            // Authentication expired or not authenticated
            document.getElementById('elchi-status').className = 'status-disconnected';
            document.getElementById('elchi-status').textContent = 'Disconnected';
            document.getElementById('elchi-login-btn').textContent = 'Login';
            document.getElementById('elchi-login-btn').onclick = showElchiLogin;
        }
    } catch (error) {
        console.log('ELCHI status check failed');
        // On error, show as disconnected
        document.getElementById('elchi-status').className = 'status-disconnected';
        document.getElementById('elchi-status').textContent = 'Disconnected';
        document.getElementById('elchi-login-btn').textContent = 'Login';
        document.getElementById('elchi-login-btn').onclick = showElchiLogin;
    }
}

// Check status on page load
document.addEventListener('DOMContentLoaded', function() {
    checkLoginStatus();
});

// Helper function to check auth status in parallel with any API request
async function checkAuthWithRequest(requestPromise) {
    // Run both the main request and auth check in parallel
    const [requestResult, ] = await Promise.allSettled([
        requestPromise,
        checkLoginStatus() // This will update UI if auth expired
    ]);
    
    return requestResult;
}