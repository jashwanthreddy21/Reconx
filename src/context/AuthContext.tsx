import React, { createContext, useContext, useEffect, useState } from 'react';
import {
  User,
  onAuthStateChanged,
  signInWithPopup,
  signOut as fbSignOut,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  updateProfile as updateFirebaseProfile,
  sendPasswordResetEmail,
} from 'firebase/auth';
import { auth, googleProvider, testFirestoreConnection } from '../lib/firebase';
import { firestoreService } from '../services/firestoreService';
import { UserProfile, UserRole } from '../types';

interface AuthContextType {
  user: User | null;
  profile: UserProfile | null;
  loading: boolean;
  authError: string | null;
  clearAuthError: () => void;
  signInWithGoogle: () => Promise<void>;
  signInWithEmail: (email: string, password: string) => Promise<void>;
  signUpWithEmail: (
    email: string,
    password: string,
    displayName: string,
    preferredRole?: UserRole
  ) => Promise<void>;
  resetPassword: (email: string) => Promise<void>;
  signOut: () => Promise<void>;
  updateRole: (role: UserRole) => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Helper to translate Firebase error codes to operator-friendly messages
export function formatAuthError(error: any): string {
  if (!error) return 'An unknown authentication error occurred.';
  const code = error.code || '';
  switch (code) {
    case 'auth/email-already-in-use':
      return 'An operator account already exists with this email address. Please sign in or use password reset.';
    case 'auth/invalid-email':
      return 'The email address format is invalid. Please check for typos.';
    case 'auth/user-not-found':
      return 'No operator account found with this email. Please check your credentials or create a new account.';
    case 'auth/wrong-password':
    case 'auth/invalid-credential':
      return 'Invalid credentials. Please verify your email and password.';
    case 'auth/weak-password':
      return 'Password is too weak. Please choose at least 6 characters (8+ recommended).';
    case 'auth/popup-closed-by-user':
      return 'Google sign-in popup was closed before authentication completed. Please try again.';
    case 'auth/popup-blocked':
      return 'Pop-up was blocked by your browser. Please allow popups for this site or use email sign-in.';
    case 'auth/too-many-requests':
      return 'Access temporarily restricted due to many failed attempts. Please wait a moment or reset your password.';
    case 'auth/network-request-failed':
      return 'Network connection issue. Please check your internet connection.';
    default:
      return error.message || 'Authentication failed. Please check your credentials.';
  }
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [authError, setAuthError] = useState<string | null>(null);

  const clearAuthError = () => setAuthError(null);

  useEffect(() => {
    testFirestoreConnection();

    const unsubscribe = onAuthStateChanged(auth, async (currentUser) => {
      setUser(currentUser);
      if (currentUser) {
        const isAdminEmail = currentUser.email?.toLowerCase() === 'cybersafe07@gmail.com';
        const authoritativeRole: UserRole = isAdminEmail ? 'admin' : 'analyst';

        try {
          let userProfile = await firestoreService.getUserProfile(currentUser.uid);
          if (!userProfile) {
            userProfile = {
              id: currentUser.uid,
              email: currentUser.email || 'operator@reconx.local',
              displayName: currentUser.displayName || (isAdminEmail ? 'Security Administrator' : 'Security Analyst'),
              photoURL: currentUser.photoURL || undefined,
              role: authoritativeRole,
              createdAt: new Date().toISOString(),
            };
            try {
              await firestoreService.saveUserProfile(userProfile);
            } catch (saveErr) {
              console.warn('Initial profile creation in Firestore skipped or permitted fallback:', saveErr);
            }
          } else if (userProfile.role !== authoritativeRole) {
            // Correct role mismatch so only specific credential is admin
            userProfile = {
              ...userProfile,
              role: authoritativeRole,
              updatedAt: new Date().toISOString(),
            };
            try {
              await firestoreService.saveUserProfile(userProfile);
            } catch (saveErr) {
              console.warn('Role mismatch save in Firestore skipped or permitted fallback:', saveErr);
            }
          }
          setProfile(userProfile);
        } catch (err) {
          console.error('Error fetching/creating user profile:', err);
          // Fallback local profile if offline or permission restricted
          setProfile({
            id: currentUser.uid,
            email: currentUser.email || 'operator@reconx.local',
            displayName: currentUser.displayName || (isAdminEmail ? 'Security Administrator' : 'Security Analyst'),
            photoURL: currentUser.photoURL || undefined,
            role: authoritativeRole,
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
    setAuthError(null);
    try {
      await signInWithPopup(auth, googleProvider);
    } catch (err: any) {
      if (err.code === 'auth/popup-closed-by-user') {
        console.warn('Google sign-in popup closed by user.');
        setAuthError('Sign-in cancelled: Google popup was closed.');
      } else {
        console.error('Google sign-in error:', err);
        setAuthError(formatAuthError(err));
      }
      throw err;
    }
  };

  const signInWithEmail = async (email: string, password: string) => {
    setAuthError(null);
    try {
      await signInWithEmailAndPassword(auth, email.trim(), password);
    } catch (err: any) {
      console.error('Email sign-in error:', err);
      const msg = formatAuthError(err);
      setAuthError(msg);
      throw new Error(msg);
    }
  };

  const signUpWithEmail = async (
    email: string,
    password: string,
    displayName: string,
    preferredRole: UserRole = 'analyst'
  ) => {
    setAuthError(null);
    try {
      const trimmedEmail = email.trim();
      const userCredential = await createUserWithEmailAndPassword(auth, trimmedEmail, password);
      const createdUser = userCredential.user;

      const trimmedName = displayName.trim() || 'Security Operator';
      try {
        await updateFirebaseProfile(createdUser, {
          displayName: trimmedName,
        });
      } catch (profileErr) {
        console.warn('Could not update Firebase user displayName:', profileErr);
      }

      const isAdminEmail = trimmedEmail.toLowerCase() === 'cybersafe07@gmail.com';
      const assignedRole: UserRole = isAdminEmail ? 'admin' : (preferredRole === 'admin' ? 'analyst' : preferredRole);

      const initialProfile: UserProfile = {
        id: createdUser.uid,
        email: trimmedEmail,
        displayName: trimmedName,
        role: assignedRole,
        createdAt: new Date().toISOString(),
      };

      try {
        await firestoreService.saveUserProfile(initialProfile);
      } catch (storeErr) {
        console.warn('Could not save user profile to Firestore immediately:', storeErr);
      }
      setProfile(initialProfile);
    } catch (err: any) {
      console.error('Email sign-up error:', err);
      const msg = formatAuthError(err);
      setAuthError(msg);
      throw new Error(msg);
    }
  };

  const resetPassword = async (email: string) => {
    setAuthError(null);
    try {
      await sendPasswordResetEmail(auth, email.trim());
    } catch (err: any) {
      console.error('Password reset error:', err);
      const msg = formatAuthError(err);
      setAuthError(msg);
      throw new Error(msg);
    }
  };

  const signOut = async () => {
    try {
      await fbSignOut(auth);
      setProfile(null);
      setAuthError(null);
    } catch (err) {
      console.error('Sign-out error:', err);
    }
  };

  const updateRole = async (newRole: UserRole) => {
    if (!profile || !user) return;
    const isAdminEmail = user.email?.toLowerCase() === 'cybersafe07@gmail.com';
    const targetRole: UserRole = !isAdminEmail && newRole === 'admin' ? 'analyst' : newRole;
    const updated = { ...profile, role: targetRole, updatedAt: new Date().toISOString() };
    setProfile(updated);
    try {
      await firestoreService.saveUserProfile(updated);
    } catch (err) {
      console.error('Could not persist updated role:', err);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        profile,
        loading,
        authError,
        clearAuthError,
        signInWithGoogle,
        signInWithEmail,
        signUpWithEmail,
        resetPassword,
        signOut,
        updateRole,
      }}
    >
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
