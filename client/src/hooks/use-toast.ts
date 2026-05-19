import toast from 'react-hot-toast';

interface ToastOptions {
  title?: string;
  description?: string;
  variant?: 'default' | 'destructive';
}

export function useToast() {
  return {
    toast: ({ title, description, variant }: ToastOptions) => {
      const msg = description || title || '';
      if (variant === 'destructive') {
        toast.error(msg);
      } else {
        toast.success(msg);
      }
    },
  };
}
