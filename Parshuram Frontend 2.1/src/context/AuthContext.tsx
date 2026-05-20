
import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { User } from '../types';
import api from '../../src/api/axios';

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  // Expose the initialization state so components don't fetch data prematurely
  isInitialized: boolean; 
  login: (email: string, password: string) => Promise<boolean>;
  logout: () => void;
  register: (employeeId: string, email: string, role: string, department: string) => Promise<{ success: boolean; credentials?: { username: string; password: string } }>;
  resetPassword: (email: string) => Promise<boolean>;
  verifyOTP: (otp: string) => Promise<boolean>;
  setNewPassword: (password: string) => Promise<boolean>;
  requestDeviceAccess: (email: string, password: string) => Promise<'approved' | 'pending' | 'rejected'>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

//const API_BASE_URL = 'http://localhost:3001/api';

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isInitialized, setIsInitialized] = useState(false); // New state to manage loading on mount

  // --- API Helper to fetch user data and role ---
  const fetchUserRole = async (sessionId: string) => {
    try {
      // Endpoint implemented in SOC/controllers/auth-controller.js
      const response = await api.get('/auth/user', {
  headers: { Authorization: `Bearer ${sessionId}` }
});
      
      if (response.status == 200) {
        const userData = response.data;
        const loggedInUser: User = {
          id: sessionId,
          email: userData.email,
          role: userData.role, 
          employeeId: userData.employeeId || 'EMP_N/A',
          department: userData.department || 'Security Operations',
        };
        setUser(loggedInUser);
        setIsAuthenticated(true);
      } else {
        // Token invalid or expired
        localStorage.removeItem('sessionId');
        setIsAuthenticated(false);
      }
    } catch (error) {
      console.error('Failed to fetch user data:', error);
      localStorage.removeItem('sessionId');
      setIsAuthenticated(false);
    } finally {
        setIsInitialized(true); // Always stop initializing regardless of success/fail
    }
  };

  // --- EFFECT: Check for session on mount ---
  useEffect(() => {
    const sessionId = localStorage.getItem('sessionId');
    if (sessionId) {
      fetchUserRole(sessionId);
    } else {
      // If no session ID is found, initialization is complete (no user)
      setIsInitialized(true); 
    }
  }, []); 

  const requestDeviceAccess = async (email: string, password: string): Promise<'approved' | 'pending' | 'rejected'> => {
    if (email === 'user@parshuram.com' && password === "user@123") {
      return 'pending';
    }
    if (email === 'rejected@parshuram.com' && password === 'rejected') {
      return 'rejected';
    }
    return 'approved';
  };

  const login = async (email: string, password: string): Promise<boolean> => {
    try {
      const response = await api.post('/auth/login', { email, password });

      if (response.status == 200) {
        const { sessionId } = response.data;
        localStorage.setItem('sessionId', sessionId);
        
        // Fetch full user role and details before setting state
        // This relies on the backend immediately validating the sessionID we just received
        await fetchUserRole(sessionId); 
        
        return true;
      }
      return false;
    } catch (error) {
      console.error('Login failed:', error);
      return false;
    }
  };

  const logout = async () => {
    const sessionId = localStorage.getItem('sessionId');
    if (sessionId) {
      await api.post('/auth/logout', {}, {
  headers: { Authorization: `Bearer ${sessionId}` }
});
    }
    setUser(null);
    setIsAuthenticated(false);
    localStorage.removeItem('sessionId');
  };

  const register = async (employeeId: string, email: string, role: string, department: string): Promise<{ success: boolean; credentials?: { username: string; password: string } }> => {
    try {
      // ... (rest of registration logic)
     const response = await api.post('/auth/add-member', {
  name: email.split('@')[0],
  email,
  password: 'default-password', 
  role: role.replace('soc-', '').toUpperCase(),
}, {
  headers: { Authorization: `Bearer ${localStorage.getItem('sessionId')}` }
});

if (response.status === 200) {
  return { success: true, credentials: { username: email, password: 'default-password' } };
}

      return { success: false };
    } catch (error) {
      console.error('Registration failed:', error);
      return { success: false };
    }
  };

  const resetPassword = async (email: string): Promise<boolean> => {
  const response = await api.post('/auth/forgot-password', { email });
  return response.data.success;
};

const verifyOTP = async (otp: string): Promise<boolean> => {
  const response = await api.post('/auth/verify-otp', { otp });
  return response.data.success;
};

const setNewPassword = async (password: string): Promise<boolean> => {
  const response = await api.post('/auth/reset-password', { password });
  return response.data.success;
};

  return (
    <AuthContext.Provider value={{
      user,
      isAuthenticated,
      isInitialized, // Export new state
      login,
      logout,
      register,
      resetPassword,
      verifyOTP,
      setNewPassword,
      requestDeviceAccess
    }}>
      {children}
    </AuthContext.Provider>
  );
};
