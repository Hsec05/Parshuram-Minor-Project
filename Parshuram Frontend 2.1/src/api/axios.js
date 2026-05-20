import axios from 'axios';

// Create the axios instance
const api = axios.create({
  baseURL: 'http://localhost:3001/api', // replace with your API base URL
  withCredentials: true, 
  timeout: 20000,
  headers: {
    'Content-Type': 'application/json'
  }
});

// Add request interceptor to automatically attach token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('sessionId');// use your cookie-based token
    if (token) {
      config.headers = config.headers || {};
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Optional: Add a response interceptor for global error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      console.error('Session expired or invalid. Please log in again.');
      // You can redirect to login page here if needed
      // window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Helper to get cookie value
function getCookie(name) {
  const nameEQ = name + '=';
  const ca = document.cookie.split(';');
  for (let i = 0; i < ca.length; i++) {
    let c = ca[i];
    while (c.charAt(0) === ' ') c = c.substring(1);
    if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length);
  }
  return null;
}

export default api;
