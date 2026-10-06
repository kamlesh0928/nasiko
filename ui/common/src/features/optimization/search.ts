/**
 * /optimization search keys (plans/feat-optimization-page.md R7A, C5): TokenOps' window keys, plus `slice`, the chart
 * bar a click picked (ISO 8601 `start/end`; `lead.ts` `parseSlice` ignores one outside the window; not `from`/`to`:
 * those are the custom window's dates), and By agent's sort and Show all.
 */
import { z } from 'zod'
import { sharedSearchSchema } from '@/app/shell/context'
import { flag, text } from '@/lib/search'

/**
 * By agent's sort keys. Here, not in breakdown.ts: the route's schema loads with the app shell, so this module imports
 * nothing of the page (review: the shell budget).
 */
const AGENT_SORTS = ['without', 'sent', 'saved', 'requests', 'name'] as const
export type AgentSort = (typeof AGENT_SORTS)[number]

export const optimizationSearchSchema = sharedSearchSchema.extend({
  slice: text.optional().catch(undefined),
  /** By agent's column (R7B): history volume first; a header click replaces history. */
  sort: z.enum(AGENT_SORTS).default('without').catch('without'),
  /** By agent's "Show all N". */
  all: flag.optional().catch(undefined),
  // Mock-only (read by the mock bootstrap from the URL): kept as written, so `?mock=optimization-classic` survives
  // the router's search validation instead of being dropped as an unknown TokenOps variant.
  mock: text.optional().catch(undefined),
})

export type OptimizationSearch = z.infer<typeof optimizationSearchSchema>
