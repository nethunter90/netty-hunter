import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/**
 * Merge class strings so later Tailwind utilities win over earlier conflicting
 * ones (e.g. an override `h-8` correctly beats a base `h-9` instead of both being
 * emitted with an arbitrary winner). clsx flattens conditional/array/object
 * inputs; twMerge resolves Tailwind class conflicts. This is what makes the `ui/`
 * component library's `className` override contract actually work.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
