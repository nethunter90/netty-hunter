import { type ButtonHTMLAttributes, forwardRef } from 'react';
import { cn } from '@/lib/utils';

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'secondary' | 'destructive' | 'outline' | 'ghost' | 'link' | 'hack' | 'hackPrimary' | 'hackDanger';
  size?: 'default' | 'sm' | 'lg' | 'icon' | 'hack';
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'default', size = 'default', ...props }, ref) => {
    const variants: Record<string, string> = {
      default: 'bg-hack-accent text-hack-bg hover:bg-hack-accent/90',
      secondary: 'bg-hack-surface text-hack-text border border-hack-border hover:bg-hack-muted',
      destructive: 'bg-hack-red text-white hover:bg-hack-red/90',
      outline: 'border border-hack-border bg-transparent hover:bg-hack-muted text-hack-text',
      ghost: 'hover:bg-hack-muted text-hack-dim hover:text-hack-text',
      link: 'text-hack-accent underline-offset-4 hover:underline',
      // Compact "hack" variants reproduce the legacy .hack-btn* CSS exactly, so
      // migrating off those global classes is visually neutral. Pair with size="hack".
      hack: 'border border-hack-border bg-hack-surface text-hack-text font-medium hover:border-hack-accent hover:text-hack-accent hover:bg-hack-accent/5',
      hackPrimary: 'bg-hack-accent text-hack-bg border border-hack-accent font-semibold hover:bg-hack-green hover:shadow-lg hover:shadow-hack-accent/20 active:scale-95',
      hackDanger: 'bg-hack-red/10 text-hack-red border border-hack-red/30 font-medium hover:bg-hack-red/20',
    };
    const sizes: Record<string, string> = {
      default: 'h-9 px-4 py-2 text-sm',
      sm: 'h-7 px-3 text-xs',
      lg: 'h-11 px-8 text-base',
      icon: 'h-9 w-9',
      hack: 'px-3 py-1.5 rounded text-xs', // matches .hack-btn geometry (rounded, not rounded-md)
    };
    return (
      <button
        ref={ref}
        className={cn(
          'inline-flex items-center justify-center rounded-md font-mono transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hack-accent focus-visible:ring-offset-1 focus-visible:ring-offset-hack-bg disabled:opacity-50 disabled:pointer-events-none',
          variants[variant],
          sizes[size],
          className
        )}
        {...props}
      />
    );
  }
);
Button.displayName = 'Button';
