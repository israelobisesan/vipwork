const BACKEND_URL = window.location.origin;

// Replace with your live Paystack public key (starts with pk_live_)
const PAYSTACK_PUBLIC_KEY = 'pk_test_your_copied_public_key_here';

function authHeaders() {
    const token = localStorage.getItem('active_token');
    return token ? { 'Authorization': 'Bearer ' + token } : {};
}