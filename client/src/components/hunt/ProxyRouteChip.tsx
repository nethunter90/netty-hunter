interface Props {
  proxyId: string;
  burned?: boolean;
}

export function ProxyRouteChip({ proxyId, burned }: Props) {
  const label = proxyId === 'direct' ? '⬤ direct' : `⬤ ${proxyId}`;
  const color = burned
    ? 'text-amber-400 border-amber-400/30'
    : proxyId === 'direct'
      ? 'text-zinc-500 border-zinc-700'
      : 'text-emerald-400 border-emerald-400/30';
  return (
    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${color}`}>
      {label}
    </span>
  );
}
