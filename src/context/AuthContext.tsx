import React, { createContext, useContext, useEffect, useState } from 'react';
import { User, onAuthStateChanged, signInWithPopup, signOut as fbSignOut } from 'firebase/auth';
import { auth, googleProvider, testFirestoreConnection } from '../lib/firebase';
import { firestoreService } from '../services/firestoreService';
import { UserProfile, UserRole } from '../types';

interface AuthContextType {
  user: User | null;
  profile: UserProfile | null;
  loading: boolean;
  signInWithGoogle: () => Promise<void>;
  signOut: () => Promise<void>;
  updateRole: (role: UserRole) => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    testFirestoreConnection();

    const unsubscribe = onAuthStateChanged(auth, async (currentUser) => {
      setUser(currentUser);
      if (currentUser) {
        try {
          let userProfile = await firestoreService.getUserProfile(currentUser.uid);
          if (!userProfile) {
            const isAdminEmail = currentUser.email?.toLowerCase() === 'cybersafe07@gmail.com';
            userProfile = {
              id: currentUser.uid,
              email: currentUser.email || 'operator@reconx.local',
              displayName: currentUser.displayName || 'Security Operator',
              photoURL: currentUser.photoURL || undefined,
              role: isAdminEmail ? 'admin' : 'analyst',
              createdAt: new Date().toISOString(),
            };
            await firestoreService.saveUserProfile(userProfile);
          }
          setProfile(userProfile);
        } catch (err) {
          console.error('Error fetching/creating user profile:', err);
          // Fallback local profile if offline
          setProfile({
            id: currentUser.uid,
            email: currentUser.email || 'operator@reconx.local',
            displayName: currentUser.displayName || 'Security Operator',
            photoURL: currentUser.photoURL || undefined,
            role: currentUser.email?.toLowerCase() === 'cybersafe07@gmail.com' ? 'admin' : 'analyst',
            createdAt: new Date().toISOString(),
          });
        }
      } else {
        setProfile(null);
      }
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  const signInWithGoogle = async () => {
    try {
      await signInWithPopup(auth, googleProvider);
    } catch (err: any) {
      console.error('Sign-in error:', err);
      throw err;
    }
  };

  const signOut = async () => {
    try {
      await fbSignOut(auth);
      setProfile(null);
    } catch (err) {
      console.error('Sign-out error:', err);
    }
  };

  const updateRole = async (newRole: UserRole) => {
    if (!profile) return;
    const updated = { ...profile, role: newRole, updatedAt: new Date().toISOString() };
    setProfile(updated);
    try {
      await firestoreService.saveUserProfile(updated);
    } catch (err) {
      console.error('Could not persist updated role:', err);
    }
  };

  return (
    <AuthContext.Provider value={{ user, profile, loading, signInWithGoogle, signOut, updateRole }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
