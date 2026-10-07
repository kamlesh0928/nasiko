import { skipToken, useQuery } from '@tanstack/react-query'
import { createFileRoute, redirect } from '@tanstack/react-router'
import { useSyncExternalStore } from 'react'
import { useSlots } from '@/app/edition-context'
import { AppShell } from '@/app/shell/AppShell'
import { BuildToasts } from '@/features/deploy/components/BuildToasts'
import { copy as deployCopy } from '@/features/deploy/copy'
import { followedCount, subscribeFollower } from '@/features/deploy/follower'
import { useGuideHiddenNav } from '@/features/onboarding/api'
import { meQuery } from '@/lib/api/auth'
import { ApiError } from '@/lib/api/client'
import { isSignedOutLocally } from '@/lib/session'

/**
 * Auth guard for everything under `_app/` (plan A17, A18). `/api/me` answers first; a
 * 401 sends the user to /login with an allow-listed relative redirect. Other errors
 * (e.g. server down) fall through so the page can render its own message, and the sidebar's
 * account row says "Account unavailable" (plans/feat-app-shell.md eng D7).
 */
export const Route = createFileRoute('/_app')({
  beforeLoad: async ({ context, location }) => {
    // After a failed logout the cookie may still work: this browser stays signed out (review D1).
    if (isSignedOutLocally()) {
      throw redirect({
        to: '/login',
        search: { redirect: location.href, expired: undefined, signout: 'failed' },
      })
    }
    try {
      await context.queryClient.ensureQueryData(meQuery)
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        throw redirect({
          to: '/login',
          search: { redirect: location.href, expired: undefined, signout: undefined },
        })
      }
    }
  },
  component: AppLayout,
})

const NONE: readonly string[] = []

/** The shell plus the feature pieces it shows on every page (the shell itself never imports a feature). */
function AppLayout() {
  const building = useSyncExternalStore(subscribeFollower, followedCount)
  const guideHidden = useGuideHiddenNav()
  // A layer's own hidden items (EE: Access control for members).
  const navHidden = useSlots().navHidden
  const layer = useQuery({ queryKey: ['nav-hidden'], queryFn: skipToken, ...navHidden?.query })
  const layerHidden = navHidden ? navHidden.hidden(layer.data) : NONE
  return (
    <AppShell
      end={<BuildToasts />}
      hidden={[...guideHidden, ...layerHidden]}
      badges={
        building
          ? { '/agents': { count: building, label: deployCopy.toast.agentsBadge(building) } }
          : undefined
      }
    />
  )
}
