// components/ui/dialog.tsx
import * as React from 'react';

interface DialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  children: React.ReactNode;
}

export const Dialog: React.FC<DialogProps> = ({ 
  open, 
  onOpenChange, 
  children 
}) => {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      {/* Backdrop */}
      <div 
        className="fixed inset-0 bg-black bg-opacity-25 transition-opacity" 
        onClick={() => onOpenChange(false)}
      />
      
      {/* Dialog positioning */}
      <div className="fixed inset-0 flex items-center justify-center p-4">
        {/* Dialog content */}
        <div 
          className="relative w-full max-w-md transform overflow-hidden rounded-lg bg-white p-6 text-left shadow-xl transition-all"
          onClick={(e) => e.stopPropagation()}
        >
          {children}
        </div>
      </div>
    </div>
  );
};

export const DialogContent: React.FC<{
  children: React.ReactNode;
}> = ({ children }) => {
  return (
    <div className="mt-2">
      {children}
    </div>
  );
};

export const DialogHeader: React.FC<{
  children: React.ReactNode;
}> = ({ children }) => {
  return (
    <div className="mb-4">
      {children}
    </div>
  );
};

export const DialogTitle: React.FC<{
  children: React.ReactNode;
}> = ({ children }) => {
  return (
    <h3 className="text-lg font-medium leading-6 text-gray-900">
      {children}
    </h3>
  );
};

export const DialogFooter: React.FC<{
  children: React.ReactNode;
}> = ({ children }) => {
  return (
    <div className="mt-4 flex justify-end space-x-2">
      {children}
    </div>
  );
};