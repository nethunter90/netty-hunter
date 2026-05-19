import { type HTMLAttributes } from 'react';
import { cn } from '@/lib/utils';

export interface BadgeProps extends HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'secondary' | 'destructive' | 'outline';
}

export function Badge({ className, variant = 'default', ...props }: BadgeProps) {
  const variants: Record<string, string> = {
    default: 'bg-hack-accent/10 text-hack-accent border border-hack-accent/30',
    secondary: 'bg-hack-surface text-hack-dim border border-hack-border',
    destructive: 'bg-hack-red/10 text-hack-red border border-hack-red/30',
    outline: 'border border-hack-border text-hack-text',
  };
  return (
    <div
      className={cn(
        'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-mono font-medium transition-colors',
        variants[variant],
        className
      )}
      {...props}
    />
  );
}
