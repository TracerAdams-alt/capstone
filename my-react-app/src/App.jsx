import { useState, useEffect } from 'react';
import Login from './components/Login.jsx';
import Register from './components/Register.jsx';
import Dashboard from './components/Dashboard.jsx';

function App() {
  const [token, setToken] = useState(null);
  const [user, setUser] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [showRegister, setShowRegister] = useState(false);

  // Check for existing token on app load
  useEffect(() => {
    const storedToken = localStorage.getItem('token');
    if (storedToken) {
      setToken(storedToken);
      // Verify token and get user data
      verifyToken(storedToken);
    } else {
      setIsLoading(false);
    }
  }, []);

  const verifyToken = async (authToken) => {
    try {
      const response = await fetch('http://localhost:3000/api/me', {
        headers: {
          'Authorization': `Bearer ${authToken}`,
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        const data = await response.json();
        setUser(data.user);
        setToken(authToken);
      } else {
        // Token is invalid, remove it
        localStorage.removeItem('token');
        localStorage.removeItem('refreshToken');
        setToken(null);
        setUser(null);
      }
    } catch (error) {
      console.error('Token verification failed:', error);
      localStorage.removeItem('token');
      localStorage.removeItem('refreshToken');
      setToken(null);
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogin = (authData) => {
    setToken(authData.token);
    setUser(authData.user);
    localStorage.setItem('token', authData.token);
    localStorage.setItem('refreshToken', authData.refreshToken);
  };

  const handleRegister = (authData) => {
    setToken(authData.token);
    setUser(authData.user);
    localStorage.setItem('token', authData.token);
    localStorage.setItem('refreshToken', authData.refreshToken);
    setShowRegister(false);
  };

  const handleLogout = () => {
    setToken(null);
    setUser(null);
    localStorage.removeItem('token');
    localStorage.removeItem('refreshToken');
  };

  const switchToRegister = () => {
    setShowRegister(true);
  };

  const switchToLogin = () => {
    setShowRegister(false);
  };

  if (isLoading) {
    return (
      <div className="loading-container">
        <div className="loading-spinner"></div>
        <p>Loading...</p>
      </div>
    );
  }

  return (
    <div className="app">
      {!token ? (
        <div className="auth-container">
          {showRegister ? (
            <Register 
              onRegister={handleRegister} 
              onSwitchToLogin={switchToLogin}
            />
          ) : (
            <Login 
              onLogin={handleLogin} 
              onSwitchToRegister={switchToRegister}
            />
          )}
        </div>
      ) : (
        <Dashboard 
          user={user} 
          onLogout={handleLogout}
          token={token}
        />
      )}
    </div>
  );
}

export default App;