import React from 'react';
import { Shield, Clock } from 'lucide-react';

const WaitingPage: React.FC = () => {
  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full text-center">
        <div className="flex items-center justify-center space-x-2 mb-4">
          <Shield className="h-12 w-12 text-blue-500" />
          <h1 className="text-3xl font-bold text-white">Parshuram</h1>
        </div>
        <h2 className="text-xl text-gray-300">Awaiting Approval</h2>
        <p className="mt-2 text-sm text-gray-400">
          Your request to access the system is pending administrator approval.
        </p>
        <div className="mt-8">
          <Clock className="h-16 w-16 text-yellow-500 mx-auto animate-pulse" />
        </div>
      </div>
    </div>
  );
};

export default WaitingPage;