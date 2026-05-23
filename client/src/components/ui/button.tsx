import { type ButtonHTMLAttributes, forwardRef } from 'react';
import { cn } from '@/lib/utils';

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'secondary' | 'destructive' | 'outline' | 'ghost' | 'link';
  size?: 'default' | 'sm' | 'lg' | 'icon';
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
    };
    const sizes: Record<string, string> = {
      default: 'h-9 px-4 py-2 text-sm',
      sm: 'h-7 px-3 text-xs',
      lg: 'h-11 px-8 text-base',
      icon: 'h-9 w-9',
    };
    return (
      <button
        ref={ref}
        className={cn(
          'inline-flex items-center justify-center rounded-md font-mono transition-colors focus-visible:outline-none disabled:opacity-50 disabled:pointer-events-none',
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
