import React, { createContext, useContext, useState, useEffect } from 'react';
import { apiClient } from '../services/apiClient';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const saved = localStorage.getItem('cyberthreat_auth_user');
    return saved ? JSON.parse(saved) : null;
  });
  const [deviceId, setDeviceId] = useState(() => {
    return localStorage.getItem('cyberthreat_device_id') || 'DEV-HOST';
  });
  const [isLoading, setIsLoading] = useState(false);
  const [authError, setAuthError] = useState(null);

  useEffect(() => {
    // Initialize and persist a unique client device ID for this physical endpoint
    let clientDevId = localStorage.getItem('cyberthreat_client_device_id');
    if (!clientDevId || clientDevId === 'DEV_ORIGIN_123' || clientDevId === 'DEV-HOST' || clientDevId === 'UNKNOWN') {
      clientDevId = `DEV_${Math.random().toString(36).substring(2, 8).toUpperCase()}${Date.now().toString(36).substring(4).toUpperCase()}`;
      localStorage.setItem('cyberthreat_client_device_id', clientDevId);
    }
    setDeviceId(clientDevId);
    localStorage.setItem('cyberthreat_device_id', clientDevId);

    // Validate active session
    const savedUser = localStorage.getItem('cyberthreat_auth_user');
    if (savedUser) {
      try {
        const u = JSON.parse(savedUser);
        apiClient.getCurrentUser(u.id).then(res => {
          if (!res || !res.authenticated) {
            setUser(null);
            localStorage.removeItem('cyberthreat_auth_user');
            apiClient.clearToken();
          } else {
            // Keep Chrome extension automatically paired with registered email across reloads
            const activeDevId = localStorage.getItem('cyberthreat_device_id') || deviceId;
            apiClient.pairExtension(u.email, activeDevId, u.id).catch(() => {});
          }
        }).catch(() => {});
      } catch (e) {}
    }
  }, []);

  const login = async (email, password) => {
    setIsLoading(true);
    setAuthError(null);
    try {
      const res = await apiClient.login(email, password, deviceId, navigator.userAgent || 'Windows Desktop');
      if (res && res.user) {
        setUser(res.user);
        localStorage.setItem('cyberthreat_auth_user', JSON.stringify(res.user));
        // Existing user sign-in: NEVER ask for onboarding permissions
        localStorage.setItem('cyberthreat_onboarding_completed', 'true');
        sessionStorage.removeItem('cyberthreat_just_registered');

        // Automatically sync Chrome extension pairing with active session
        try {
          await apiClient.pairExtension(res.user.email, deviceId, res.user.id);
        } catch (extErr) {
          console.warn('[Extension Pairing Notice]:', extErr.message);
        }

        setIsLoading(false);
        return res.user;
      }
      throw new Error('Invalid response from server');
    } catch (err) {
      const msg = err.message === 'Failed to fetch'
        ? 'Could not connect to CyberZen Security Cloud. Please check your internet connection and try again.'
        : (err.message || 'Login failed. Please check credentials.');
      setAuthError(msg);
      setIsLoading(false);
      throw new Error(msg);
    }
  };

  const signup = async (fullName, email, password, consentAccepted = true) => {
    setIsLoading(true);
    setAuthError(null);
    try {
      const res = await apiClient.signup(email, password, fullName, deviceId, navigator.userAgent || 'Windows Desktop', consentAccepted);
      if (res && res.user) {
        setUser(res.user);
        localStorage.setItem('cyberthreat_auth_user', JSON.stringify(res.user));
        // Only ask onboarding permissions when user registers
        sessionStorage.setItem('cyberthreat_just_registered', 'true');
        localStorage.removeItem('cyberthreat_onboarding_completed');

        // Automatically pair and configure Chrome extension for registered user
        try {
          await apiClient.pairExtension(res.user.email, deviceId, res.user.id);
        } catch (extErr) {
          console.warn('[Extension Pairing Notice]:', extErr.message);
        }

        setIsLoading(false);
        return res.user;
      }
      throw new Error('Invalid response from server');
    } catch (err) {
      const msg = err.message === 'Failed to fetch'
        ? 'Could not connect to CyberZen Security Cloud. Please check your internet connection and try again.'
        : (err.message || 'Signup failed. Please try again.');
      setAuthError(msg);
      setIsLoading(false);
      throw new Error(msg);
    }
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem('cyberthreat_auth_user');
    apiClient.clearToken();
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        authError,
        setAuthError,
        login,
        signup,
        logout
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
