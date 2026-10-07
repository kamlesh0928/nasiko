import { z } from 'zod/mini'
import { flag, opt, text } from '@/lib/search'

/**
 * URL state for the agent pages (plan §7). Junk values fall back instead of throwing, so a
 * stale link still opens the page.
 */
export const catalogSearchSchema = z.object({
  /** Untrimmed while typing (trimming here would eat the space between words); matching trims. */
  q: opt(z.string().check(z.maxLength(200))),
  tag: opt(text),
  harnesses: opt(flag),
  yours: opt(flag),
  /** The Overview's Fleet health count links here (overview design 15A, 16B); computed by `useFleetHealth` (eng R1). */
  health: opt(z.enum(['healthy', 'watch', 'action', 'unknown'])),
})
export type CatalogSearch = z.infer<typeof catalogSearchSchema>

export const MINE_TABS = [
  'all',
  'running',
  'deploying',
  'attention',
  'stopped',
  'harnesses',
] as const
export const mineSearchSchema = z.object({
  tab: opt(z.enum(MINE_TABS)),
  harnesses: opt(flag),
  /** Superusers only: whose agents to list (a UUID). */
  owner: opt(z.uuid()),
})
export type MineSearch = z.infer<typeof mineSearchSchema>

export const DETAIL_TABS = [
  'overview',
  'activity',
  'versions',
  'builds',
  'mcp',
  'access',
  'settings',
] as const
export type DetailTab = (typeof DETAIL_TABS)[number]
/** Unknown tab values are kept as strings so the page can fall back to Overview with replace-history. */
export const detailSearchSchema = z.object({
  tab: opt(z.string().check(z.trim(), z.maxLength(40))),
})

/**
 * The delete result, carried to Your agents in router history state, not the URL: a crafted
 * link can't show a fake "Deleted …" notice, and long runtime-error lists aren't cut.
 */
export interface DeletedNote {
  name: string
  errors: string[]
  stopped: number
}

declare module '@tanstack/react-router' {
  interface HistoryState {
    agentDeleted?: DeletedNote
  }
}
