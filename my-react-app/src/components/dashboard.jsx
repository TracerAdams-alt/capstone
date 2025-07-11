import { useState } from 'react';

export default function Dashboard({ user, onLogout, token }) {
  const [activeTab, setActiveTab] = useState('profile');
  const [profileData, setProfileData] = useState({
    username: user?.username || '',
    email: user?.email || ''
  });
  const [passwordData, setPasswordData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleProfileUpdate = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setIsLoading(true);

    try {
      const response = await fetch('http://localhost:3000/api/profile', {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: profileData.username,
          email: profileData.email
        }),
      });

      const data = await response.json();

      if (response.ok) {
        setSuccess('Profile updated successfully!');
        // Update local user data could be passed back to parent
      } else {
        setError(data.message || 'Profile update failed');
      }
    } catch (error) {
      console.error('Profile update error:', error);
      setError('Network error. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handlePasswordChange = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (passwordData.newPassword !== passwordData.confirmPassword) {
      setError('New passwords do not match');
      return;
    }

    if (passwordData.newPassword.length < 6) {
      setError('New password must be at least 6 characters long');
      return;
    }

    setIsLoading(true);

    try {
      const response = await fetch('http://localhost:3000/api/profile', {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          currentPassword: passwordData.currentPassword,
          newPassword: passwordData.newPassword
        }),
      });

      const data = await response.json();

      if (response.ok) {
        setSuccess('Password changed successfully!');
        setPasswordData({
          currentPassword: '',
          newPassword: '',
          confirmPassword: ''
        });
      } else {
        setError(data.message || 'Password change failed');
      }
    } catch (error) {
      console.error('Password change error:', error);
      setError('Network error. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      await fetch('http://localhost:3000/api/logout', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      onLogout();
    }
  };

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <h1>Welcome, {user?.username}!</h1>
        <button 
          className="logout-button"
          onClick={handleLogout}
        >
          Logout
        </button>
      </div>

      <div className="dashboard-content">
        <div className="tabs">
          <button 
            className={`tab ${activeTab === 'profile' ? 'active' : ''}`}
            onClick={() => setActiveTab('profile')}
          >
            Profile
          </button>
          <button 
            className={`tab ${activeTab === 'password' ? 'active' : ''}`}
            onClick={() => setActiveTab('password')}
          >
            Change Password
          </button>
          <button 
            className={`tab ${activeTab === 'info' ? 'active' : ''}`}
            onClick={() => setActiveTab('info')}
          >
            Account Info
          </button>
        </div>

        {error && (
          <div className="error-message">
            {error}
          </div>
        )}

        {success && (
          <div className="success-message">
            {success}
          </div>
        )}

        {activeTab === 'profile' && (
          <div className="tab-content">
            <h3>Update Profile</h3>
            <form onSubmit={handleProfileUpdate} className="profile-form">
              <div className="form-group">
                <label htmlFor="username">Username</label>
                <input 
                  type="text" 
                  id="username"
                  value={profileData.username} 
                  onChange={(e) => setProfileData({
                    ...profileData,
                    username: e.target.value
                  })} 
                  required 
                  disabled={isLoading}
                />
              </div>

              <div className="form-group">
                <label htmlFor="email">Email</label>
                <input 
                  type="email" 
                  id="email"
                  value={profileData.email} 
                  onChange={(e) => setProfileData({
                    ...profileData,
                    email: e.target.value
                  })} 
                  required 
                  disabled={isLoading}
                />
              </div>

              <button 
                type="submit" 
                className="update-button"
                disabled={isLoading}
              >
                {isLoading ? 'Updating...' : 'Update Profile'}
              </button>
            </form>
          </div>
        )}

        {activeTab === 'password' && (
          <div className="tab-content">
            <h3>Change Password</h3>
            <form onSubmit={handlePasswordChange} className="password-form">
              <div className="form-group">
                <label htmlFor="currentPassword">Current Password</label>
                <input 
                  type="password" 
                  id="currentPassword"
                  value={passwordData.currentPassword} 
                  onChange={(e) => setPasswordData({
                    ...passwordData,
                    currentPassword: e.target.value
                  })} 
                  required 
                  disabled={isLoading}
                />
              </div>

              <div className="form-group">
                <label htmlFor="newPassword">New Password</label>
                <input 
                  type="password" 
                  id="newPassword"
                  value={passwordData.newPassword} 
                  onChange={(e) => setPasswordData({
                    ...passwordData,
                    newPassword: e.target.value
                  })} 
                  required 
                  disabled={isLoading}
                  minLength={6}
                />
              </div>

              <div className="form-group">
                <label htmlFor="confirmNewPassword">Confirm New Password</label>
                <input 
                  type="password" 
                  id="confirmNewPassword"
                  value={passwordData.confirmPassword} 
                  onChange={(e) => setPasswordData({
                    ...passwordData,
                    confirmPassword: e.target.value
                  })} 
                  required 
                  disabled={isLoading}
                  minLength={6}
                />
              </div>

              <button 
                type="submit" 
                className="update-button"
                disabled={isLoading}
              >
                {isLoading ? 'Changing...' : 'Change Password'}
              </button>
            </form>
          </div>
        )}

        {activeTab === 'info' && (
          <div className="tab-content">
            <h3>Account Information</h3>
            <div className="info-grid">
              <div className="info-item">
                <strong>Username:</strong> {user?.username}
              </div>
              <div className="info-item">
                <strong>Email:</strong> {user?.email}
              </div>
              <div className="info-item">
                <strong>Role:</strong> {user?.role}
              </div>
              <div className="info-item">
                <strong>Account Created:</strong> {new Date(user?.createdAt).toLocaleDateString()}
              </div>
              <div className="info-item">
                <strong>Status:</strong> {user?.isActive ? 'Active' : 'Inactive'}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}