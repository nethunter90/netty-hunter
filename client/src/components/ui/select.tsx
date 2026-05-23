import {
  createContext, useContext, useState,
  type HTMLAttributes, type ReactNode, forwardRef
} from 'react';
import { cn } from '@/lib/utils';
import { ChevronDown } from 'lucide-react';

interface SelectCtx {
  value: string;
  onValueChange: (v: string) => void;
  open: boolean;
  setOpen: (o: boolean) => void;
}
const SelectContext = createContext<SelectCtx>({ value: '', onValueChange: () => {}, open: false, setOpen: () => {} });

interface SelectProps {
  value?: string;
  defaultValue?: string;
  onValueChange?: (value: string) => void;
  children?: ReactNode;
}

export function Select({ value, defaultValue = '', onValueChange = () => {}, children }: SelectProps) {
  const [internal, setInternal] = useState(defaultValue);
  const [open, setOpen] = useState(false);
  const controlled = value !== undefined;
  const current = controlled ? value : internal;
  const handleChange = (v: string) => {
    if (!controlled) setInternal(v);
    onValueChange(v);
    setOpen(false);
  };
  return (
    <SelectContext.Provider value={{ value: current, onValueChange: handleChange, open, setOpen }}>
      <div className="relative">{children}</div>
    </SelectContext.Provider>
  );
}

export const SelectTrigger = forwardRef<HTMLButtonElement, HTMLAttributes<HTMLButtonElement>>(
  ({ className, children, ...props }, ref) => {
    const { setOpen, open } = useContext(SelectContext);
    return (
      <button
        ref={ref}
        type="button"
        onClick={() => setOpen(!open)}
        className={cn(
          'flex h-9 w-full items-center justify-between rounded-md border border-hack-border bg-hack-bg px-3 py-2 text-sm font-mono text-hack-text placeholder:text-hack-dim focus:outline-none focus:ring-1 focus:ring-hack-accent disabled:opacity-50',
          className
        )}
        {...props}
      >
        {children}
        <ChevronDown className="h-4 w-4 opacity-50 ml-2 flex-shrink-0" />
      </button>
    );
  }
);
SelectTrigger.displayName = 'SelectTrigger';

export function SelectValue({ placeholder }: { placeholder?: string }) {
  const { value } = useContext(SelectContext);
  return <span className="truncate">{value || <span className="text-hack-dim">{placeholder}</span>}</span>;
}

export const SelectContent = forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>(
  ({ className, children, ...props }, ref) => {
    const { open } = useContext(SelectContext);
    if (!open) return null;
    return (
      <div
        ref={ref}
        className={cn(
          'absolute z-50 mt-1 w-full rounded-md border border-hack-border bg-hack-surface shadow-lg max-h-60 overflow-auto',
          className
        )}
        {...props}
      >
        {children}
      </div>
    );
  }
);
SelectContent.displayName = 'SelectContent';

export function SelectItem({ value, children, className }: { value: string; children?: ReactNode; className?: string }) {
  const { onValueChange, value: selected } = useContext(SelectContext);
  return (
    <div
      onClick={() => onValueChange(value)}
      className={cn(
        'relative flex cursor-pointer select-none items-center px-3 py-2 text-sm font-mono text-hack-text hover:bg-hack-muted',
        selected === value && 'bg-hack-accent/10 text-hack-accent',
        className
      )}
    >
      {children}
    </div>
  );
}

export function SelectGroup({ children }: { children?: ReactNode }) {
  return <div>{children}</div>;
}

export function SelectLabel({ children, className }: { children?: ReactNode; className?: string }) {
  return <div className={cn('px-3 py-1.5 text-xs font-mono text-hack-dim', className)}>{children}</div>;
}
